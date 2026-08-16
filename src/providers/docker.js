import { createServer } from 'node:net';
import { commandExists, run, runJson } from '../process.js';
import { ProcessError, ProviderUnavailableError, OwnershipError } from '../errors.js';
import { canonicalResourceRefs, createMetadata, deriveWorkspaceIdentity, labelHash, providerLabels, readMetadata, workspaceName, WORKSPACE_RUNTIME } from '../metadata.js';
import { createWorkspaceSecrets, getWorkspaceToken, rotateWorkspaceCredentials, selectGrantedCredentials } from '../auth.js';
import { requireDockerEgress, validateImage } from '../policy.js';
import { waitForHttpHealth } from '../health.js';
import { PROVIDER_MODEL_AUTH_FILE, PROVIDER_SECRET_DIRECTORY, PROVIDER_TOKEN_FILE, runtimeCommand, runtimeEnvironment } from '../runtime-command.js';
import { cleanupTransaction, createTransaction } from '../lifecycle.js';
import { readWorkspaceState, stateRoot, writeWorkspaceState } from '../state-store.js';
import { createSourceSnapshot } from '../snapshot.js';
import { ARTIFACT_LIMITS, RUNTIME_ARTIFACT_SCRIPT } from '../artifact.js';

export function createDockerProvider({ policy, sourceDirectory }) {
  const provider = 'docker';

  async function preflight() {
    requireDockerEgress(policy);
    if (!commandExists('docker')) throw new ProviderUnavailableError('Docker CLI is not available', { provider });
    await run('docker', ['info'], { timeoutMs: 15_000 });
    return { provider, available: true, diagnostics: [] };
  }

  function configure(info) {
    const identity = deriveWorkspaceIdentity(info, provider);
    const image = validateImage(policy, policy.defaultImage);
    const refs = canonicalResourceRefs(identity.providerResourceID, provider, policy);
    return {
      ...info,
      name: workspaceName(identity.providerResourceID, provider),
      directory: WORKSPACE_RUNTIME.directory,
      extra: createMetadata(info, provider, { ...policy, defaultImage: image }, refs, identity),
    };
  }

  async function create(info, env = {}) {
    await preflight();
    const meta = readMetadata(info, provider, policy);
    const identity = identityFromMetadata(meta);
    const refs = canonicalResourceRefs(meta.providerResourceID, provider, policy);
    const image = validateImage(policy, meta.imageDigest);
    await run('docker', ['image', 'inspect', image], { timeoutMs: 20_000 }).catch(() => run('docker', ['pull', image], { timeoutMs: 300_000 }));

    await createTransaction(identity, async (transaction) => {
      const sourceSnapshot = await createSourceSnapshot(sourceDirectory, { temporaryRoot: stateRoot() });
      try {
      if (!transaction.recovering) await assertResourcesAbsent(refs);
      await transaction.bindSnapshot(sourceSnapshot.generation);
      const secrets = await createWorkspaceSecrets(meta.providerResourceID, selectGrantedCredentials(policy, env));
      const hostPort = await availableStablePort(meta.providerResourceID);
      await transaction.update({ hostPort, imageDigest: image });
      await transaction.create(`network:${refs.network}`, async () => {
        await run('docker', ['network', 'create', '--driver', 'bridge', '--internal', ...labelArgs(providerLabels(identity, 'network')), refs.network], { timeoutMs: 60_000 });
      }, () => removeDocker('network', refs.network), () => dockerResourceExistsOwned('network', refs.network, providerLabels(identity, 'network')));
      await transaction.create(`volume:${refs.mutableVolume}`, () => run('docker', ['volume', 'create', ...labelArgs(providerLabels(identity, 'mutable-storage')), refs.mutableVolume]), () => removeDocker('volume', refs.mutableVolume), () => dockerResourceExistsOwned('volume', refs.mutableVolume, providerLabels(identity, 'mutable-storage')));
      await transaction.create(`volume:${refs.baselineVolume}`, () => run('docker', ['volume', 'create', ...labelArgs(providerLabels(identity, 'baseline-storage')), refs.baselineVolume]), () => removeDocker('volume', refs.baselineVolume), () => dockerResourceExistsOwned('volume', refs.baselineVolume, providerLabels(identity, 'baseline-storage')));
      await transaction.create(`volume:${refs.secretVolume}`, () => run('docker', ['volume', 'create', ...labelArgs(providerLabels(identity, 'secrets')), refs.secretVolume]), () => removeDocker('volume', refs.secretVolume), () => dockerResourceExistsOwned('volume', refs.secretVolume, providerLabels(identity, 'secrets')));

      await transaction.create(
        `seed:${refs.mutableVolume}`,
        () => seedVolume(image, refs.mutableVolume, WORKSPACE_RUNTIME.directory, sourceSnapshot.archivePath, sourceSnapshot.generation),
        async () => undefined,
        () => verifyDockerSeed(image, refs.mutableVolume, WORKSPACE_RUNTIME.directory, sourceSnapshot.generation),
      );
      await transaction.create(
        `seed:${refs.baselineVolume}`,
        () => seedVolume(image, refs.baselineVolume, WORKSPACE_RUNTIME.baselineDirectory, sourceSnapshot.archivePath, sourceSnapshot.generation),
        async () => undefined,
        () => verifyDockerSeed(image, refs.baselineVolume, WORKSPACE_RUNTIME.baselineDirectory, sourceSnapshot.generation),
      );
      await updateSecretVolume(image, refs.secretVolume, secrets.token, secrets.modelAuth);
      await transaction.create(`container:${refs.gateway}`, () => startEgressGateway({ runtimeImage: image, refs, identity, egress: policy.egress }), () => removeDocker('container', refs.gateway), () => dockerResourceExistsOwned('container', refs.gateway, providerLabels(identity, 'egress-gateway')));
      await transaction.create(
        `network-attachment:${refs.gateway}:${refs.network}`,
        () => run('docker', ['network', 'connect', '--alias', 'workspace-egress', refs.network, refs.gateway], { timeoutMs: 60_000 }),
        () => disconnectDockerNetwork(refs.network, refs.gateway),
        () => dockerContainerHasNetwork(refs.gateway, refs.network),
      );
      const runtimePolicy = { ...policy, egress: { ...policy.egress, proxyUrl: 'http://workspace-egress:3128' } };
      const runtimeArgs = [
        'run', '-d', '--name', refs.runtime,
        ...labelArgs(providerLabels(identity, 'runtime')),
        '--network', refs.network,
        '--user', '1000:1000',
        '--read-only', '--tmpfs', '/tmp:rw,exec,nosuid,size=256m',
        '--security-opt', 'no-new-privileges', '--cap-drop', 'ALL',
        '--pids-limit', String(policy.docker.pidsLimit),
        '-v', `${refs.mutableVolume}:${WORKSPACE_RUNTIME.directory}`,
        '-v', `${refs.baselineVolume}:${WORKSPACE_RUNTIME.baselineDirectory}:ro`,
        '-v', `${refs.secretVolume}:${PROVIDER_SECRET_DIRECTORY}:ro`,
        '-w', WORKSPACE_RUNTIME.directory,
        '-e', 'OPENCODE_EXPERIMENTAL_WORKSPACES=true',
      ];
      for (const [key, value] of Object.entries(runtimeEnvironment({ policy: runtimePolicy }, PROVIDER_TOKEN_FILE))) runtimeArgs.push('-e', `${key}=${value}`);
      if (policy.docker.memoryLimit) runtimeArgs.push('--memory', String(policy.docker.memoryLimit));
      if (policy.docker.cpuLimit) runtimeArgs.push('--cpus', String(policy.docker.cpuLimit));
      runtimeArgs.push(image, 'sh', '-lc', runtimeCommand(PROVIDER_TOKEN_FILE));
      await transaction.create(`container:${refs.runtime}`, () => run('docker', runtimeArgs, { timeoutMs: 120_000 }), () => removeDocker('container', refs.runtime), () => dockerResourceExistsOwned('container', refs.runtime, providerLabels(identity, 'runtime')));
      await transaction.create(`container:${refs.access}`, () => startAccessProxy({ image, refs, identity, hostPort }), () => removeDocker('container', refs.access), () => dockerResourceExistsOwned('container', refs.access, providerLabels(identity, 'access-proxy')));
      await transaction.create(
        `network-attachment:${refs.access}:${refs.network}`,
        () => run('docker', ['network', 'connect', refs.network, refs.access], { timeoutMs: 60_000 }),
        () => disconnectDockerNetwork(refs.network, refs.access),
        () => dockerContainerHasNetwork(refs.access, refs.network),
      );
      await verifyDockerWorkspace(meta);
      await health(info);
      } finally {
        await sourceSnapshot.dispose();
      }
    });
  }

  async function target(info) {
    const meta = readMetadata(info, provider, policy);
    await verifyDockerWorkspace(meta);
    const state = await readOwnedState(meta);
    if (!state?.hostPort) throw new Error('Docker workspace stable target port is missing');
    const port = await inspectPort(meta.resourceRefs.access);
    if (port !== String(state.hostPort)) throw new OwnershipError('Docker workspace target port does not match persisted state');
    return { type: 'remote', url: `http://127.0.0.1:${port}`, headers: { 'x-openchamber-workspace-token': await getWorkspaceToken(meta.authRef) } };
  }

  async function health(info) {
    const remote = await target(info);
    await waitForHttpHealth(remote.url, remote.headers);
    return { ok: true };
  }

  async function remove(info) {
    const meta = readMetadata(info, provider, policy);
    const refs = canonicalResourceRefs(meta.providerResourceID, provider, policy);
    const identity = identityFromMetadata(meta);
    return cleanupTransaction(meta.providerResourceID, async (cleanup) => {
      await verifyExistingResources(refs, identity);
      await cleanup.remove(`container:${refs.access}`, () => removeDocker('container', refs.access));
      await cleanup.remove(`container:${refs.runtime}`, () => removeDocker('container', refs.runtime));
      await cleanup.remove(`container:${refs.gateway}`, () => removeDocker('container', refs.gateway));
      await cleanup.remove(`network:${refs.network}`, () => removeDocker('network', refs.network));
      await cleanup.remove(`volume:${refs.secretVolume}`, () => removeDocker('volume', refs.secretVolume));
      if (!policy.retention.preserveOnDelete) {
        await cleanup.remove(`volume:${refs.mutableVolume}`, () => removeDocker('volume', refs.mutableVolume));
        await cleanup.remove(`volume:${refs.baselineVolume}`, () => removeDocker('volume', refs.baselineVolume));
      } else {
        cleanup.retain(`volume:${refs.mutableVolume}`);
        cleanup.retain(`volume:${refs.baselineVolume}`);
      }
    });
  }

  async function list(context) {
    if (!commandExists('docker')) throw new ProviderUnavailableError('Docker CLI is not available', { provider });
    const projectID = context?.instance?.project?.id;
    if (!projectID) throw new Error('Docker workspace discovery requires an authoritative project ID');
    const filters = ['--filter', 'label=openchamber.managed=true', '--filter', 'label=openchamber.workspace.provider=docker', '--filter', 'label=openchamber.resource.role=runtime', '--filter', `label=openchamber.project.id=${labelHash(projectID)}`];
    const { stdout } = await run('docker', ['ps', '-a', ...filters, '--format', '{{json .}}'], { timeoutMs: 20_000 });
    const listed = [];
    for (const line of stdout.split('\n').filter(Boolean)) {
      const row = JSON.parse(line);
      const providerResourceID = readDockerLabel(row.Labels, 'openchamber.resource.id');
      if (!providerResourceID) continue;
      const state = await readWorkspaceState(providerResourceID);
      if (!state || state.projectID !== String(projectID) || state.provider !== provider) continue;
      const identity = { provider, providerResourceID, projectID: String(projectID), controlPlaneWorkspaceID: state.controlPlaneWorkspaceID, originalControlPlaneWorkspaceID: state.originalControlPlaneWorkspaceID ?? state.controlPlaneWorkspaceID };
      listed.push({
        type: provider,
        name: workspaceName(providerResourceID, provider),
        branch: null,
        directory: WORKSPACE_RUNTIME.directory,
        projectID: String(projectID),
        extra: createMetadata({ id: state.controlPlaneWorkspaceID, projectID: String(projectID) }, provider, policy, canonicalResourceRefs(providerResourceID, provider, policy), identity),
      });
    }
    return listed;
  }

  async function exportWorkspace(info) {
    const meta = readMetadata(info, provider, policy);
    await verifyDockerWorkspace(meta);
    const state = await readOwnedState(meta);
    const snapshot = await runJson('docker', ['exec', meta.resourceRefs.runtime, 'node', '-e', RUNTIME_ARTIFACT_SCRIPT, WORKSPACE_RUNTIME.baselineDirectory, WORKSPACE_RUNTIME.directory, state.baselineGeneration, String(ARTIFACT_LIMITS.maxTextBytes), String(ARTIFACT_LIMITS.maxBlobBytes), String(ARTIFACT_LIMITS.maxTotalBytes)], { timeoutMs: 120_000, maxOutputBytes: ARTIFACT_LIMITS.maxOutputBytes, sensitiveOutput: true, sensitiveValues: [RUNTIME_ARTIFACT_SCRIPT] });
    return { ...snapshot, provider, providerResourceID: meta.providerResourceID };
  }

  async function reconcile(info) {
    const meta = readMetadata(info, provider, policy);
    try {
      await verifyDockerWorkspace(meta);
      const state = await readOwnedState(meta);
      const remote = await target(info);
      await waitForHttpHealth(remote.url, remote.headers, { timeoutMs: 15_000 });
      const repaired = [];
      if (state.lifecycle !== 'ready') { await writeWorkspaceState(meta.providerResourceID, { ...state, lifecycle: 'ready', reconciledAt: new Date().toISOString() }); repaired.push('operation-journal'); }
      return { provider, providerResourceID: meta.providerResourceID, status: 'ready', diagnostics: [], repaired };
    } catch (error) {
      return { provider, providerResourceID: meta.providerResourceID, status: 'degraded', diagnostics: [{ code: error?.code ?? 'WORKSPACE_RECONCILE_FAILED', message: error instanceof Error ? error.message : String(error) }], repaired: [] };
    }
  }

  async function rotateCredentials(info, request = {}) {
    const meta = readMetadata(info, provider, policy);
    await verifyDockerWorkspace(meta);
    await readOwnedState(meta);
    const image = validateImage(policy, meta.imageDigest);
    if (request.modelAuth != null && policy.credentials.modelAuth !== 'explicit-opencode-auth-content') throw new Error('Model authentication grants are disabled by workspace policy');
    return rotateWorkspaceCredentials(meta.providerResourceID, request, async ({ token, modelAuth }) => { await verifyDockerWorkspace(meta); await updateSecretVolume(image, meta.resourceRefs.secretVolume, token, modelAuth); await run('docker', ['restart', meta.resourceRefs.runtime], { timeoutMs: 120_000 }); });
  }

  return { kind: provider, configure, create, target, remove, list, health, exportWorkspace, reconcile, rotateCredentials, validate: preflight };
}

async function seedVolume(image, volume, mountPath, archivePath, generation) {
  await run('docker', [
    'run', '--rm', '--user', '1000:1000', '--network', 'none', '--security-opt', 'no-new-privileges', '--cap-drop', 'ALL',
    '-v', `${volume}:${mountPath}`,
    '-v', `${archivePath}:/source.tar:ro`, image, 'sh', '-lc',
    `set -eu; tar --no-same-owner -xf /source.tar -C ${mountPath}; mkdir -p ${mountPath}/.openchamber-runtime; printf '%s' '${generation}' > ${mountPath}/.openchamber-runtime/source-generation`,
  ], { timeoutMs: 300_000 });
}

async function verifyDockerSeed(image, volume, mountPath, generation) {
  try {
    const { stdout } = await run('docker', [
      'run', '--rm', '--user', '1000:1000', '--network', 'none', '--security-opt', 'no-new-privileges', '--cap-drop', 'ALL',
      '-v', `${volume}:${mountPath}:ro`, image, 'node', '-e',
      `process.stdout.write(require('fs').readFileSync('${mountPath}/.openchamber-runtime/source-generation','utf8'))`,
    ], { timeoutMs: 60_000 });
    return stdout === generation;
  } catch {
    return false;
  }
}

async function updateSecretVolume(image, secretVolume, token, modelAuth) {
  const payload = JSON.stringify({ token, modelAuth });
  await run('docker', ['run', '--rm', '-i', '--user', '1000:1000', '--network', 'none', '--security-opt', 'no-new-privileges', '--cap-drop', 'ALL', '-v', `${secretVolume}:${PROVIDER_SECRET_DIRECTORY}`, image, 'node', '-e', `const fs=require('fs');let s='';const write=(p,v)=>{try{fs.chmodSync(p,0o600)}catch(e){if(e.code!=='ENOENT')throw e}fs.writeFileSync(p,v,{mode:0o600});fs.chmodSync(p,0o400)};process.stdin.on('data',c=>s+=c);process.stdin.on('end',()=>{const v=JSON.parse(s);write('${PROVIDER_TOKEN_FILE}',v.token);if(v.modelAuth===undefined)fs.rmSync('${PROVIDER_MODEL_AUTH_FILE}',{force:true});else write('${PROVIDER_MODEL_AUTH_FILE}',v.modelAuth)})`], { input: payload, timeoutMs: 60_000, sensitiveOutput: true });
}

async function startAccessProxy({ image, refs, identity, hostPort }) {
  await run('docker', [
    'run', '-d', '--name', refs.access, ...labelArgs(providerLabels(identity, 'access-proxy')),
    '--network', 'bridge', '--user', '1000:1000', '--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m',
    '--security-opt', 'no-new-privileges', '--cap-drop', 'ALL', '--pids-limit', '64',
    '-p', `127.0.0.1:${hostPort}:${WORKSPACE_RUNTIME.port}`,
    '-e', `OPENCHAMBER_ACCESS_PROXY_TARGET=${refs.runtime}`, image, 'node', '-e', accessProxyScript(),
  ], { timeoutMs: 120_000 });
}

async function startEgressGateway({ runtimeImage, refs, identity, egress }) {
  const common = [
    'run', '-d', '--name', refs.gateway, ...labelArgs(providerLabels(identity, 'egress-gateway')),
    '--network', 'bridge', '--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m',
    '--security-opt', 'no-new-privileges', '--cap-drop', 'ALL', '--pids-limit', '64',
  ];
  if (egress.mode === 'managed') {
    await run('docker', [...common, '--user', '10001:10001', '-e', `OPENCHAMBER_RESOURCE_ID=${identity.providerResourceID}`, '-e', `OPENCHAMBER_EGRESS_POLICY=${JSON.stringify(egress.gatewayPolicy)}`, egress.gatewayImage], { timeoutMs: 120_000 });
    return;
  }
  const proxy = new URL(egress.proxyUrl);
  const targetHost = proxy.hostname === '127.0.0.1' || proxy.hostname === 'localhost' ? 'host.docker.internal' : proxy.hostname;
  const targetPort = proxy.port || (proxy.protocol === 'http:' ? '80' : '443');
  await run('docker', [
    ...common, '--user', '1000:1000', '--add-host', 'host.docker.internal:host-gateway',
    '-e', `OPENCHAMBER_PROXY_HOST=${targetHost}`, '-e', `OPENCHAMBER_PROXY_PORT=${targetPort}`,
    '-e', `OPENCHAMBER_PROXY_TLS=${proxy.protocol === 'https:' ? 'true' : 'false'}`, '-e', `OPENCHAMBER_PROXY_SERVERNAME=${proxy.hostname}`,
    runtimeImage, 'node', '-e', fixedProxyBridgeScript(),
  ], { timeoutMs: 120_000 });
}

function fixedProxyBridgeScript() {
  return "const net=require('node:net'),tls=require('node:tls');const host=process.env.OPENCHAMBER_PROXY_HOST,port=Number(process.env.OPENCHAMBER_PROXY_PORT),secure=process.env.OPENCHAMBER_PROXY_TLS==='true',servername=process.env.OPENCHAMBER_PROXY_SERVERNAME;if(!host||!port)throw new Error('proxy target required');net.createServer(s=>{const ready=()=>s.pipe(u).pipe(s);const u=secure?tls.connect({host,port,servername:net.isIP(servername)?undefined:servername},ready):net.connect(port,host,ready);u.setTimeout(5000,()=>{u.destroy();s.destroy()});u.once(secure?'secureConnect':'connect',()=>u.setTimeout(0));u.on('error',()=>s.destroy());s.on('error',()=>u.destroy())}).listen(3128,'0.0.0.0');";
}

function accessProxyScript() {
  return `const net=require('node:net');const target=process.env.OPENCHAMBER_ACCESS_PROXY_TARGET;net.createServer((socket)=>{const upstream=net.connect(${WORKSPACE_RUNTIME.port},target,()=>{upstream.setTimeout(0);socket.pipe(upstream).pipe(socket)});upstream.setTimeout(5000,()=>{upstream.destroy();socket.destroy()});upstream.on('error',()=>socket.destroy());socket.on('error',()=>upstream.destroy())}).listen(${WORKSPACE_RUNTIME.port},'0.0.0.0');`;
}

async function verifyDockerWorkspace(meta) {
  const identity = identityFromMetadata(meta);
  const refs = meta.resourceRefs;
  await verifyDockerResource('container', refs.runtime, providerLabels(identity, 'runtime'), (entry) => hardenedContainer(entry) && exactNetworks(entry, [refs.network]));
  await verifyDockerResource('container', refs.access, providerLabels(identity, 'access-proxy'), (entry) => hardenedContainer(entry) && exactNetworks(entry, ['bridge', refs.network]) && (entry?.Mounts ?? []).length === 0);
  await verifyDockerResource('container', refs.gateway, providerLabels(identity, 'egress-gateway'), (entry) => hardenedContainer(entry, ['1000:1000', '10001:10001']) && exactNetworks(entry, ['bridge', refs.network]) && (entry?.Mounts ?? []).length === 0);
  await verifyDockerResource('volume', refs.mutableVolume, providerLabels(identity, 'mutable-storage'));
  await verifyDockerResource('volume', refs.baselineVolume, providerLabels(identity, 'baseline-storage'));
  await verifyDockerResource('volume', refs.secretVolume, providerLabels(identity, 'secrets'));
  await verifyDockerResource('network', refs.network, providerLabels(identity, 'network'), (entry) => entry.Internal === true);
}

async function verifyExistingResources(refs, identity) {
  for (const [kind, name, role] of [['container', refs.runtime, 'runtime'], ['container', refs.access, 'access-proxy'], ['container', refs.gateway, 'egress-gateway'], ['volume', refs.mutableVolume, 'mutable-storage'], ['volume', refs.baselineVolume, 'baseline-storage'], ['volume', refs.secretVolume, 'secrets'], ['network', refs.network, 'network']]) {
    await verifyDockerResource(kind, name, providerLabels(identity, role)).catch((error) => { if (!isDockerNotFound(error)) throw error; });
  }
}

async function verifyDockerResource(kind, name, expectedLabels, extraCheck) {
  const inspected = await runJson('docker', kind === 'container' ? ['inspect', name] : [kind, 'inspect', name], { timeoutMs: 20_000 });
  const entry = inspected?.[0];
  const labels = kind === 'container' ? entry?.Config?.Labels : entry?.Labels;
  for (const [key, value] of Object.entries(expectedLabels)) if (labels?.[key] !== value) throw new OwnershipError(`Docker ${kind} ownership mismatch for ${name}: ${key}`);
  if (extraCheck && !extraCheck(entry)) throw new OwnershipError(`Docker ${kind} security configuration mismatch: ${name}`);
}

async function dockerResourceExistsOwned(kind, name, expectedLabels) {
  try {
    await verifyDockerResource(kind, name, expectedLabels);
    return true;
  } catch (error) {
    if (isDockerNotFound(error)) return false;
    throw error;
  }
}

async function assertResourcesAbsent(refs) {
  for (const [kind, name] of [['container', refs.runtime], ['container', refs.access], ['container', refs.gateway], ['volume', refs.mutableVolume], ['volume', refs.baselineVolume], ['volume', refs.secretVolume], ['network', refs.network]]) {
    const args = kind === 'container' ? ['inspect', name] : [kind, 'inspect', name];
    const exists = await runJson('docker', args, { timeoutMs: 20_000 }).then(() => true).catch((error) => { if (isDockerNotFound(error)) return false; throw error; });
    if (exists) throw new OwnershipError(`Docker resource collision: ${kind}/${name}`);
  }
}

async function removeDocker(kind, name) {
  const args = kind === 'container' ? ['rm', '-f', name] : [kind, 'rm', name];
  await run('docker', args, { timeoutMs: 60_000 }).catch((error) => { if (!isDockerNotFound(error)) throw error; });
}

async function disconnectDockerNetwork(network, container) {
  await run('docker', ['network', 'disconnect', '-f', network, container], { timeoutMs: 60_000 }).catch((error) => { if (!isDockerNotFound(error)) throw error; });
}

async function dockerContainerHasNetwork(container, network) {
  try {
    const inspected = await runJson('docker', ['inspect', container], { timeoutMs: 20_000 });
    return Boolean(inspected?.[0]?.NetworkSettings?.Networks?.[network]);
  } catch (error) {
    if (isDockerNotFound(error)) return false;
    throw error;
  }
}

async function inspectPort(container) {
  const deadline = Date.now() + 5_000;
  let binding;
  do {
    const inspected = await runJson('docker', ['inspect', container], { timeoutMs: 20_000 });
    const entry = inspected?.[0];
    if (entry?.State?.Running !== true) throw new Error(`Docker workspace container is not running: ${container}`);
    binding = entry?.NetworkSettings?.Ports?.[`${WORKSPACE_RUNTIME.port}/tcp`]?.[0];
    if (binding?.HostIp && binding?.HostPort) break;
    await new Promise((resolve) => setTimeout(resolve, 100));
  } while (Date.now() < deadline);
  if (binding?.HostIp !== '127.0.0.1' && binding?.HostIp !== '::1') throw new OwnershipError('Docker workspace target is not loopback-only');
  if (!binding?.HostPort) throw new Error(`Docker workspace has no localhost port mapping: ${container}`);
  return String(binding.HostPort);
}

function hardenedContainer(entry, users = ['1000:1000']) {
  const host = entry?.HostConfig ?? {};
  return users.includes(entry?.Config?.User)
    && host.ReadonlyRootfs === true
    && (host.CapDrop ?? []).includes('ALL')
    && (host.SecurityOpt ?? []).some((value) => value === 'no-new-privileges' || value === 'no-new-privileges:true');
}

function exactNetworks(entry, expected) {
  const actual = Object.keys(entry?.NetworkSettings?.Networks ?? {}).sort();
  return actual.length === expected.length && actual.every((value, index) => value === [...expected].sort()[index]);
}

async function availableStablePort(providerResourceID) {
  const digest = Number.parseInt(providerResourceID.slice(-4), 16);
  for (let offset = 0; offset < 512; offset += 1) {
    const port = 49152 + (digest + offset) % 16384;
    if (await portAvailable(port)) return port;
  }
  throw new Error('Unable to allocate a stable loopback port');
}

function portAvailable(port) {
  return new Promise((resolve) => {
    const server = createServer();
    server.once('error', () => resolve(false));
    server.listen(port, '127.0.0.1', () => server.close(() => resolve(true)));
  });
}

function identityFromMetadata(meta) {
  return { provider: meta.provider, providerResourceID: meta.providerResourceID, projectID: meta.projectID, controlPlaneWorkspaceID: meta.controlPlaneWorkspaceID, originalControlPlaneWorkspaceID: meta.originalControlPlaneWorkspaceID ?? meta.controlPlaneWorkspaceID };
}

async function readOwnedState(meta) {
  const state = await readWorkspaceState(meta.providerResourceID);
  if (!state || state.provider !== meta.provider || state.projectID !== meta.projectID || state.controlPlaneWorkspaceID !== meta.controlPlaneWorkspaceID) throw new OwnershipError('Docker workspace state identity mismatch');
  return state;
}

function labelArgs(labels) {
  return Object.entries(labels).flatMap(([key, value]) => ['--label', `${key}=${value}`]);
}

function readDockerLabel(labels, key) {
  if (typeof labels !== 'string') return undefined;
  return labels.split(',').map((part) => part.trim()).find((part) => part.startsWith(`${key}=`))?.slice(key.length + 1);
}

function isDockerNotFound(error) {
  if (!(error instanceof ProcessError)
    || error.kind !== 'exit'
    || !Number.isInteger(error.exitCode)
    || error.exitCode === 0
    || error.truncated) return false;
  const output = `${error.stderr}\n${error.stdout}`;
  return /\bNo such (?:object|container|volume|network)\b/i.test(output)
    || /\b(?:container|volume|network)\b.*\bnot found\b/i.test(output);
}
