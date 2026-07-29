import { createServer } from 'node:net';
import { basename, dirname } from 'node:path';
import { commandExists, run, runJson } from '../process.js';
import { OwnershipError, ProviderUnavailableError } from '../errors.js';
import { canonicalResourceRefs, createMetadata, deriveWorkspaceIdentity, labelHash, providerLabels, readMetadata, workspaceName, WORKSPACE_RUNTIME } from '../metadata.js';
import { createWorkspaceSecrets, getWorkspaceToken, rotateWorkspaceCredentials, selectGrantedCredentials } from '../auth.js';
import { requireAppleContainerEgress, validateImage } from '../policy.js';
import { waitForHttpHealth } from '../health.js';
import { PROVIDER_MODEL_AUTH_FILE, PROVIDER_SECRET_DIRECTORY, PROVIDER_TOKEN_FILE, runtimeCommand, runtimeEnvironment } from '../runtime-command.js';
import { cleanupTransaction, createTransaction } from '../lifecycle.js';
import { readWorkspaceState, stateRoot, writeWorkspaceState } from '../state-store.js';
import { createSourceSnapshot } from '../snapshot.js';
import { ARTIFACT_LIMITS, RUNTIME_ARTIFACT_SCRIPT } from '../artifact.js';

export function createAppleContainerProvider({ policy, sourceDirectory }) {
  const provider = 'apple-container';
  const container = (args, options = {}) => run(policy.appleContainer.cli, args, options);
  const containerJson = (args, options = {}) => runJson(policy.appleContainer.cli, args, options);

  async function preflight() {
    if (process.platform !== 'darwin') throw new ProviderUnavailableError('Apple Container is supported only on macOS', { provider, code: 'WORKSPACE_PROVIDER_UNSUPPORTED' });
    requireAppleContainerEgress(policy);
    if (policy.egress.mode === 'managed') throw new ProviderUnavailableError('Managed gateway networking for Apple Container requires live-validated multi-network attachment', { provider, code: 'WORKSPACE_PROVIDER_CAPABILITY_UNAVAILABLE' });
    if (!commandExists(policy.appleContainer.cli)) throw new ProviderUnavailableError('Apple Container CLI is not available', { provider });
    await container(['system', 'status'], { timeoutMs: 15_000 });
    return { provider, available: true, diagnostics: ['Apple Container has no exact no-new-privileges equivalent; non-root, capability drop, read-only root, and host-only networking are enforced.'] };
  }

  function configure(info) {
    const identity = deriveWorkspaceIdentity(info, provider);
    const image = validateImage(policy, policy.defaultImage);
    const refs = canonicalResourceRefs(identity.providerResourceID, provider, policy);
    return { ...info, name: workspaceName(identity.providerResourceID, provider), directory: WORKSPACE_RUNTIME.directory, extra: createMetadata(info, provider, { ...policy, defaultImage: image }, refs, identity) };
  }

  async function create(info, env = {}) {
    await preflight();
    const meta = readMetadata(info, provider, policy);
    const identity = identityFromMetadata(meta);
    const refs = canonicalResourceRefs(meta.providerResourceID, provider, policy);
    const image = validateImage(policy, meta.imageDigest);
    await container(['image', 'inspect', image], { timeoutMs: 20_000 }).catch(() => container(['image', 'pull', image], { timeoutMs: 300_000 }));
    await createTransaction(identity, async (transaction) => {
      const sourceSnapshot = await createSourceSnapshot(sourceDirectory, { temporaryRoot: stateRoot() });
      try {
      if (!transaction.recovering) await assertResourcesAbsent(containerJson, refs);
      await transaction.bindSnapshot(sourceSnapshot.generation);
      const secrets = await createWorkspaceSecrets(meta.providerResourceID, selectGrantedCredentials(policy, env));
      const hostPort = await availableStablePort(meta.providerResourceID);
      await transaction.update({ hostPort, imageDigest: image });
      await transaction.create(`network:${refs.network}`, () => container(['network', 'create', '--internal', ...labelArgs(providerLabels(identity, 'network')), refs.network], { timeoutMs: 60_000 }), () => removeResource(container, containerJson, 'network', refs.network), () => appleResourceExistsOwned(containerJson, 'network', refs.network, providerLabels(identity, 'network')));
      await transaction.create(`volume:${refs.mutableVolume}`, () => container(['volume', 'create', ...labelArgs(providerLabels(identity, 'mutable-storage')), refs.mutableVolume], { timeoutMs: 60_000 }), () => removeResource(container, containerJson, 'volume', refs.mutableVolume), () => appleResourceExistsOwned(containerJson, 'volume', refs.mutableVolume, providerLabels(identity, 'mutable-storage')));
      await transaction.create(`volume:${refs.baselineVolume}`, () => container(['volume', 'create', ...labelArgs(providerLabels(identity, 'baseline-storage')), refs.baselineVolume], { timeoutMs: 60_000 }), () => removeResource(container, containerJson, 'volume', refs.baselineVolume), () => appleResourceExistsOwned(containerJson, 'volume', refs.baselineVolume, providerLabels(identity, 'baseline-storage')));
      await transaction.create(`volume:${refs.secretVolume}`, () => container(['volume', 'create', ...labelArgs(providerLabels(identity, 'secrets')), refs.secretVolume], { timeoutMs: 60_000 }), () => removeResource(container, containerJson, 'volume', refs.secretVolume), () => appleResourceExistsOwned(containerJson, 'volume', refs.secretVolume, providerLabels(identity, 'secrets')));
      await transaction.create(
        `seed:${refs.mutableVolume}`,
        () => seedVolume(container, image, refs.mutableVolume, WORKSPACE_RUNTIME.directory, sourceSnapshot.archivePath, sourceSnapshot.generation),
        async () => undefined,
        () => verifyAppleSeed(container, image, refs.mutableVolume, WORKSPACE_RUNTIME.directory, sourceSnapshot.generation),
      );
      await transaction.create(
        `seed:${refs.baselineVolume}`,
        () => seedVolume(container, image, refs.baselineVolume, WORKSPACE_RUNTIME.baselineDirectory, sourceSnapshot.archivePath, sourceSnapshot.generation),
        async () => undefined,
        () => verifyAppleSeed(container, image, refs.baselineVolume, WORKSPACE_RUNTIME.baselineDirectory, sourceSnapshot.generation),
      );
      await updateSecretVolume(container, image, refs.secretVolume, secrets.token, secrets.modelAuth, { initialize: true });
      const inspectedNetwork = await containerJson(['network', 'inspect', refs.network], { timeoutMs: 20_000 });
      const runtimeMeta = withAppleProxy({ policy }, inspectedNetwork?.[0]);
      const args = appleRuntimeArgs({ policy, identity, refs, image, hostPort, runtimeMeta });
      await transaction.create(`container:${refs.runtime}`, () => container(args, { timeoutMs: 120_000 }), () => removeResource(container, containerJson, 'container', refs.runtime), () => appleResourceExistsOwned(containerJson, 'container', refs.runtime, providerLabels(identity, 'runtime')));
      await verifyWorkspace(containerJson, meta);
      await health(info);
      } finally {
        await sourceSnapshot.dispose();
      }
    });
  }

  async function target(info) {
    const meta = readMetadata(info, provider, policy);
    await verifyWorkspace(containerJson, meta);
    const state = await readOwnedState(meta);
    if (!state?.hostPort) throw new Error('Apple Container stable target port is missing');
    const inspected = await containerJson(['inspect', meta.resourceRefs.runtime], { timeoutMs: 20_000 });
    const port = inspectPort(inspected?.[0]);
    if (String(port) !== String(state.hostPort)) throw new OwnershipError('Apple Container target port does not match persisted state');
    return { type: 'remote', url: `http://127.0.0.1:${port}`, headers: { 'x-openchamber-workspace-token': await getWorkspaceToken(meta.authRef) } };
  }

  async function health(info) {
    const remote = await target(info);
    await waitForHttpHealth(remote.url, remote.headers, { timeoutMs: 90_000 });
    return { ok: true };
  }

  async function remove(info) {
    const meta = readMetadata(info, provider, policy);
    const refs = canonicalResourceRefs(meta.providerResourceID, provider, policy);
    return cleanupTransaction(meta.providerResourceID, async (cleanup) => {
      await verifyExisting(containerJson, meta);
      await cleanup.remove(`container:${refs.runtime}`, () => removeResource(container, containerJson, 'container', refs.runtime));
      await cleanup.remove(`network:${refs.network}`, () => removeResource(container, containerJson, 'network', refs.network));
      await cleanup.remove(`volume:${refs.secretVolume}`, () => removeResource(container, containerJson, 'volume', refs.secretVolume));
      if (!policy.retention.preserveOnDelete) {
        await cleanup.remove(`volume:${refs.mutableVolume}`, () => removeResource(container, containerJson, 'volume', refs.mutableVolume));
        await cleanup.remove(`volume:${refs.baselineVolume}`, () => removeResource(container, containerJson, 'volume', refs.baselineVolume));
      } else {
        cleanup.retain(`volume:${refs.mutableVolume}`);
        cleanup.retain(`volume:${refs.baselineVolume}`);
      }
    });
  }

  async function list(context) {
    const projectID = context?.instance?.project?.id;
    if (!projectID) throw new Error('Apple Container workspace discovery requires an authoritative project ID');
    const { stdout } = await container(['list', '--all', '--format', 'json'], { timeoutMs: 20_000 });
    const result = [];
    for (const row of stdout.trim() ? JSON.parse(stdout) : []) {
      const labels = row.configuration?.labels ?? {};
      if (labels['openchamber.managed'] !== 'true' || labels['openchamber.workspace.provider'] !== provider || labels['openchamber.resource.role'] !== 'runtime' || labels['openchamber.project.id'] !== labelHash(projectID)) continue;
      const providerResourceID = labels['openchamber.resource.id'];
      const state = providerResourceID ? await readWorkspaceState(providerResourceID) : null;
      if (!state || state.projectID !== String(projectID) || state.provider !== provider) continue;
      const identity = { provider, providerResourceID, projectID: String(projectID), controlPlaneWorkspaceID: state.controlPlaneWorkspaceID, originalControlPlaneWorkspaceID: state.originalControlPlaneWorkspaceID ?? state.controlPlaneWorkspaceID };
      result.push({ type: provider, name: workspaceName(providerResourceID, provider), branch: null, directory: WORKSPACE_RUNTIME.directory, projectID: String(projectID), extra: createMetadata({ id: state.controlPlaneWorkspaceID, projectID: String(projectID) }, provider, policy, canonicalResourceRefs(providerResourceID, provider, policy), identity) });
    }
    return result;
  }

  async function exportWorkspace(info) {
    const meta = readMetadata(info, provider, policy);
    await verifyWorkspace(containerJson, meta);
    const state = await readOwnedState(meta);
    const snapshot = await containerJson(['exec', meta.resourceRefs.runtime, 'node', '-e', RUNTIME_ARTIFACT_SCRIPT, WORKSPACE_RUNTIME.baselineDirectory, WORKSPACE_RUNTIME.directory, state.baselineGeneration, String(ARTIFACT_LIMITS.maxTextBytes), String(ARTIFACT_LIMITS.maxBlobBytes), String(ARTIFACT_LIMITS.maxTotalBytes)], { timeoutMs: 120_000, maxOutputBytes: ARTIFACT_LIMITS.maxOutputBytes, sensitiveOutput: true, sensitiveValues: [RUNTIME_ARTIFACT_SCRIPT] });
    return { ...snapshot, provider, providerResourceID: meta.providerResourceID };
  }

  async function reconcile(info) {
    const meta = readMetadata(info, provider, policy);
    try {
      await verifyWorkspace(containerJson, meta);
      const state = await readOwnedState(meta);
      const repaired = [];
      const inspected = await containerJson(['inspect', meta.resourceRefs.runtime], { timeoutMs: 20_000 });
      if (inspected?.[0]?.status?.state !== 'running') {
        await container(['start', meta.resourceRefs.runtime], { timeoutMs: 60_000 });
        repaired.push('runtime-restart');
      }
      const remote = await target(info);
      await waitForHttpHealth(remote.url, remote.headers, { timeoutMs: 15_000 });
      if (state.lifecycle !== 'ready') { await writeWorkspaceState(meta.providerResourceID, { ...state, lifecycle: 'ready', reconciledAt: new Date().toISOString() }); repaired.push('operation-journal'); }
      return { provider, providerResourceID: meta.providerResourceID, status: 'ready', diagnostics: [], repaired };
    } catch (error) {
      return { provider, providerResourceID: meta.providerResourceID, status: 'degraded', diagnostics: [{ code: error?.code ?? 'WORKSPACE_RECONCILE_FAILED', message: error instanceof Error ? error.message : String(error) }], repaired: [] };
    }
  }

  async function rotateCredentials(info, request = {}) {
    const meta = readMetadata(info, provider, policy);
    await verifyWorkspace(containerJson, meta);
    const state = await readOwnedState(meta);
    const image = validateImage(policy, meta.imageDigest);
    if (request.modelAuth != null && policy.credentials.modelAuth !== 'explicit-opencode-auth-content') throw new Error('Model authentication grants are disabled by workspace policy');
    return rotateWorkspaceCredentials(meta.providerResourceID, request, async ({ token, modelAuth }) => {
      const runtimeExists = await verifyCredentialRotationResources(containerJson, meta);
      if (runtimeExists) await removeResource(container, containerJson, 'container', meta.resourceRefs.runtime);
      await updateSecretVolume(container, image, meta.resourceRefs.secretVolume, token, modelAuth);
      const inspectedNetwork = await containerJson(['network', 'inspect', meta.resourceRefs.network], { timeoutMs: 20_000 });
      const runtimeMeta = withAppleProxy({ policy }, inspectedNetwork?.[0]);
      const args = appleRuntimeArgs({ policy, identity: identityFromMetadata(meta), refs: meta.resourceRefs, image, hostPort: state.hostPort, runtimeMeta });
      await container(args, { timeoutMs: 120_000 });
      await verifyWorkspace(containerJson, meta);
      const inspected = await containerJson(['inspect', meta.resourceRefs.runtime], { timeoutMs: 20_000 });
      const port = inspectPort(inspected?.[0]);
      if (String(port) !== String(state.hostPort)) throw new OwnershipError('Apple Container rotated runtime port does not match persisted state');
      await waitForHttpHealth(`http://127.0.0.1:${port}`, { 'x-openchamber-workspace-token': token }, { timeoutMs: 90_000 });
    });
  }

  return { kind: provider, configure, create, target, remove, list, health, exportWorkspace, reconcile, rotateCredentials, validate: preflight };
}

async function seedVolume(container, image, volume, mountPath, archivePath, generation) {
  await container(['run', '--rm', '--user', '0:0', '--network', 'none', '--cap-drop', 'ALL', '--cap-add', 'CHOWN', '--volume', `${volume}:${mountPath}`, '--mount', `type=bind,source=${dirname(archivePath)},target=/source,readonly`, image, 'sh', '-lc', `set -eu; tar --no-same-owner -xf /source/${basename(archivePath)} -C ${mountPath}; mkdir -p ${mountPath}/.openchamber-runtime; printf '%s' '${generation}' > ${mountPath}/.openchamber-runtime/source-generation; chown -R 1000:1000 ${mountPath}`], { timeoutMs: 300_000 });
}

async function verifyAppleSeed(container, image, volume, mountPath, generation) {
  try {
    const { stdout } = await container(['run', '--rm', '--user', '1000:1000', '--network', 'none', '--cap-drop', 'ALL', '--volume', `${volume}:${mountPath}:ro`, image, 'node', '-e', `process.stdout.write(require('fs').readFileSync('${mountPath}/.openchamber-runtime/source-generation','utf8'))`], { timeoutMs: 60_000 });
    return stdout === generation;
  } catch {
    return false;
  }
}

async function updateSecretVolume(container, image, secretVolume, token, modelAuth, { initialize = false } = {}) {
  const payload = JSON.stringify({ token, modelAuth, initialize });
  const args = ['run', '--rm', '-i', '--user', initialize ? '0:0' : '1000:1000', '--network', 'none', '--cap-drop', 'ALL'];
  if (initialize) args.push('--cap-add', 'CHOWN');
  args.push('--volume', `${secretVolume}:${PROVIDER_SECRET_DIRECTORY}`, image, 'node', '-e', `const fs=require('fs');let s='';const write=(p,v,i)=>{try{fs.chmodSync(p,0o600)}catch(e){if(e.code!=='ENOENT')throw e}fs.writeFileSync(p,v,{mode:0o600});fs.chmodSync(p,0o400);if(i)fs.chownSync(p,1000,1000)};process.stdin.on('data',c=>s+=c);process.stdin.on('end',()=>{const v=JSON.parse(s);write('${PROVIDER_TOKEN_FILE}',v.token,v.initialize);if(v.modelAuth===undefined)fs.rmSync('${PROVIDER_MODEL_AUTH_FILE}',{force:true});else write('${PROVIDER_MODEL_AUTH_FILE}',v.modelAuth,v.initialize);fs.chmodSync('${PROVIDER_SECRET_DIRECTORY}',0o700);if(v.initialize)fs.chownSync('${PROVIDER_SECRET_DIRECTORY}',1000,1000)})`);
  await container(args, { input: payload, timeoutMs: 60_000, sensitiveOutput: true });
}

function appleRuntimeArgs({ policy, identity, refs, image, hostPort, runtimeMeta }) {
  const args = [
    'run', '--detach', '--name', refs.runtime, ...labelArgs(providerLabels(identity, 'runtime')),
    '--network', refs.network, '--user', '1000:1000', '--read-only', '--cap-drop', 'ALL',
    '--tmpfs', '/tmp',
    '--publish', `127.0.0.1:${hostPort}:${WORKSPACE_RUNTIME.port}`,
    '--volume', `${refs.mutableVolume}:${WORKSPACE_RUNTIME.directory}`,
    '--volume', `${refs.baselineVolume}:${WORKSPACE_RUNTIME.baselineDirectory}:ro`,
    '--volume', `${refs.secretVolume}:${PROVIDER_SECRET_DIRECTORY}:ro`,
    '--workdir', WORKSPACE_RUNTIME.directory,
    '--env', 'OPENCODE_EXPERIMENTAL_WORKSPACES=true',
  ];
  for (const [key, value] of Object.entries(runtimeEnvironment(runtimeMeta, PROVIDER_TOKEN_FILE))) args.push('--env', `${key}=${value}`);
  if (policy.appleContainer.memoryLimit) args.push('--memory', String(policy.appleContainer.memoryLimit));
  if (policy.appleContainer.cpuLimit) args.push('--cpus', String(policy.appleContainer.cpuLimit));
  args.push(image, 'sh', '-lc', runtimeCommand(PROVIDER_TOKEN_FILE));
  return args;
}

async function verifyWorkspace(containerJson, meta) {
  const identity = identityFromMetadata(meta);
  await verifyResource(containerJson, 'container', meta.resourceRefs.runtime, providerLabels(identity, 'runtime'));
  await verifyResource(containerJson, 'volume', meta.resourceRefs.mutableVolume, providerLabels(identity, 'mutable-storage'));
  await verifyResource(containerJson, 'volume', meta.resourceRefs.baselineVolume, providerLabels(identity, 'baseline-storage'));
  await verifyResource(containerJson, 'volume', meta.resourceRefs.secretVolume, providerLabels(identity, 'secrets'));
  await verifyResource(containerJson, 'network', meta.resourceRefs.network, providerLabels(identity, 'network'), (entry) => entry?.configuration?.mode === 'hostOnly');
}

async function verifyExisting(containerJson, meta) {
  const identity = identityFromMetadata(meta);
  for (const [kind, name, role] of [['container', meta.resourceRefs.runtime, 'runtime'], ['volume', meta.resourceRefs.mutableVolume, 'mutable-storage'], ['volume', meta.resourceRefs.baselineVolume, 'baseline-storage'], ['volume', meta.resourceRefs.secretVolume, 'secrets'], ['network', meta.resourceRefs.network, 'network']]) await verifyResource(containerJson, kind, name, providerLabels(identity, role)).catch((error) => { if (!isNotFound(error)) throw error; });
}

async function verifyCredentialRotationResources(containerJson, meta) {
  const identity = identityFromMetadata(meta);
  await verifyResource(containerJson, 'volume', meta.resourceRefs.mutableVolume, providerLabels(identity, 'mutable-storage'));
  await verifyResource(containerJson, 'volume', meta.resourceRefs.baselineVolume, providerLabels(identity, 'baseline-storage'));
  await verifyResource(containerJson, 'volume', meta.resourceRefs.secretVolume, providerLabels(identity, 'secrets'));
  await verifyResource(containerJson, 'network', meta.resourceRefs.network, providerLabels(identity, 'network'), (entry) => entry?.configuration?.mode === 'hostOnly');
  return verifyResource(containerJson, 'container', meta.resourceRefs.runtime, providerLabels(identity, 'runtime')).then(() => true).catch((error) => {
    if (isNotFound(error)) return false;
    throw error;
  });
}

async function verifyResource(containerJson, kind, name, expected, check) {
  const inspected = await containerJson([kind === 'container' ? 'inspect' : kind, ...(kind === 'container' ? [] : ['inspect']), name], { timeoutMs: 20_000 });
  const entry = inspected?.[0];
  const labels = entry?.configuration?.labels ?? entry?.labels ?? {};
  for (const [key, value] of Object.entries(expected)) if (labels[key] !== value) throw new OwnershipError(`Apple Container ${kind} ownership mismatch for ${name}: ${key}`);
  if (check && !check(entry)) throw new OwnershipError(`Apple Container ${kind} security configuration mismatch: ${name}`);
}

async function appleResourceExistsOwned(containerJson, kind, name, expected) {
  try {
    await verifyResource(containerJson, kind, name, expected);
    return true;
  } catch (error) {
    if (isNotFound(error)) return false;
    throw error;
  }
}

async function assertResourcesAbsent(containerJson, refs) {
  for (const [kind, name] of [['container', refs.runtime], ['volume', refs.mutableVolume], ['volume', refs.baselineVolume], ['volume', refs.secretVolume], ['network', refs.network]]) {
    const args = kind === 'container' ? ['inspect', name] : [kind, 'inspect', name];
    const exists = await containerJson(args, { timeoutMs: 20_000 }).then(() => true).catch((error) => { if (isNotFound(error)) return false; throw error; });
    if (exists) throw new OwnershipError(`Apple Container resource collision: ${kind}/${name}`);
  }
}

async function removeResource(container, containerJson, kind, name) {
  const args = kind === 'container' ? ['delete', '--force', name] : [kind, 'delete', name];
  try {
    await container(args, { timeoutMs: 60_000 });
  } catch (error) {
    if (isNotFound(error)) return;
    const inspectArgs = kind === 'container' ? ['inspect', name] : [kind, 'inspect', name];
    const absent = await containerJson(inspectArgs, { timeoutMs: 20_000 }).then(() => false).catch((inspectError) => {
      if (isNotFound(inspectError)) return true;
      throw error;
    });
    if (!absent) throw error;
  }
}

function inspectPort(entry) {
  if (entry?.status?.state !== 'running') throw new Error(`Apple Container workspace is not running: ${entry?.id ?? '<unknown>'}`);
  const binding = entry?.configuration?.publishedPorts?.find((item) => item.containerPort === WORKSPACE_RUNTIME.port);
  if (binding?.hostAddress !== '127.0.0.1' && binding?.hostAddress !== '::1') throw new OwnershipError('Apple Container target is not loopback-only');
  if (!binding?.hostPort) throw new Error('Apple Container workspace has no localhost port mapping');
  return binding.hostPort;
}

function withAppleProxy(meta, network) {
  const proxy = meta.policy.egress.proxyUrl;
  const gateway = network?.status?.ipv4Gateway;
  if (!proxy || !gateway) return meta;
  const parsed = new URL(proxy);
  if (parsed.hostname !== '127.0.0.1' && parsed.hostname !== 'localhost') return meta;
  parsed.hostname = gateway;
  return { policy: { ...meta.policy, egress: { ...meta.policy.egress, proxyUrl: parsed.toString() } } };
}

async function availableStablePort(providerResourceID) {
  const start = 49152 + Number.parseInt(providerResourceID.slice(-4), 16) % 16384;
  for (let offset = 0; offset < 512; offset += 1) { const port = 49152 + (start - 49152 + offset) % 16384; if (await portAvailable(port)) return port; }
  throw new Error('Unable to allocate a stable loopback port');
}

function portAvailable(port) {
  return new Promise((resolve) => { const server = createServer(); server.once('error', () => resolve(false)); server.listen(port, '127.0.0.1', () => server.close(() => resolve(true))); });
}

function labelArgs(labels) {
  return Object.entries(labels).flatMap(([key, value]) => ['--label', `${key}=${value}`]);
}

function identityFromMetadata(meta) {
  return { provider: meta.provider, providerResourceID: meta.providerResourceID, projectID: meta.projectID, controlPlaneWorkspaceID: meta.controlPlaneWorkspaceID, originalControlPlaneWorkspaceID: meta.originalControlPlaneWorkspaceID ?? meta.controlPlaneWorkspaceID };
}

async function readOwnedState(meta) {
  const state = await readWorkspaceState(meta.providerResourceID);
  if (!state || state.provider !== meta.provider || state.projectID !== meta.projectID || state.controlPlaneWorkspaceID !== meta.controlPlaneWorkspaceID) throw new OwnershipError('Apple Container workspace state identity mismatch');
  return state;
}

function isNotFound(error) {
  return /not found|no such container|no such volume|does not exist/i.test(error instanceof Error ? error.message : String(error));
}
