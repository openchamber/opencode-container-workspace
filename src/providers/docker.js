import { commandExists, run, runJson, sanitizeLabelValue } from '../process.js';
import { canonicalWorkspaceLabelID } from '../label-id.js';
import { ProviderUnavailableError } from '../errors.js';
import { createExtra, readExtra, workspaceName, WORKSPACE_RUNTIME } from '../metadata.js';
import { createWorkspaceToken, deleteWorkspaceToken, getWorkspaceToken } from '../auth.js';
import { SECURE_DOCKER_NETWORK, requireDockerEgress, validateImage } from '../policy.js';
import { waitForHttpHealth } from '../health.js';
import { BASELINE_COMMAND, RUNTIME_TOKEN_FILE, runtimeCommand, runtimeEnvironment } from '../runtime-command.js';

const EXPORT_DIFF_COMMAND = 'tmp=$(mktemp); idx=$(git rev-parse --git-path index 2>/dev/null || true); if [ -n "$idx" ] && [ -f "$idx" ]; then cp "$idx" "$tmp"; fi; GIT_INDEX_FILE="$tmp" git add -N . >/dev/null 2>&1 || true; GIT_INDEX_FILE="$tmp" git diff --binary HEAD; code=$?; rm -f "$tmp"; exit $code';

export function createDockerProvider({ policy, sourceDirectory }) {
  const provider = 'docker';

  async function preflight() {
    requireDockerEgress(policy);
    if (!commandExists('docker')) throw new ProviderUnavailableError('Docker CLI is not available', { provider });
    await run('docker', ['info'], { timeoutMs: 15_000 });
  }

  function configure(info) {
    const name = workspaceName(info, provider);
    const id = canonicalWorkspaceLabelID(info.id);
    const image = validateImage(policy, info.extra?.image ?? policy.defaultImage);
    const extra = createExtra(info, provider, { ...policy, defaultImage: image }, {
      storage: { type: 'docker-volume', volume: `openchamber-ws-${id}` },
      runtime: {
        type: 'docker-container',
        container: `openchamber-ws-${id}`,
        accessContainer: `openchamber-ws-${id}-access`,
      },
    });
    return { ...info, name, directory: WORKSPACE_RUNTIME.directory, extra };
  }

  async function create(info, env) {
    await preflight();
    const meta = readExtra(info, provider);
    const image = validateImage(policy, meta.image);
    const tokenInfo = await createWorkspaceToken(info.id);
    const volume = meta.storage.volume;
    const container = meta.runtime.container;
    const accessContainer = meta.runtime.accessContainer;
    const labels = Object.entries(meta.labels).flatMap(([key, value]) => ['--label', `${key}=${value}`]);
    const runtimeLabels = [...labels, '--label', 'openchamber.workspace.role=runtime'];
    const accessLabels = [...labels, '--label', 'openchamber.workspace.role=access-proxy'];
    try {
      await run('docker', ['image', 'inspect', image], { timeoutMs: 20_000 }).catch(() => run('docker', ['pull', image], { timeoutMs: 300_000 }));
      await ensureDockerNetwork(policy);
      await run('docker', ['volume', 'create', ...labels, volume]);
      await run('docker', [
        'run', '-i', '--rm',
        '--network', 'none',
        '--security-opt', 'no-new-privileges',
        '--cap-drop', 'ALL',
        '-v', `${volume}:${WORKSPACE_RUNTIME.directory}`,
        '-v', `${sourceDirectory}:/source:ro`,
        image,
        'sh', '-lc', `cd /source && tar cf - . | tar xf - -C ${WORKSPACE_RUNTIME.directory} && ${BASELINE_COMMAND} && umask 077 && mkdir -p ${WORKSPACE_RUNTIME.directory}/.openchamber && cat > ${RUNTIME_TOKEN_FILE}`,
      ], { timeoutMs: 300_000, input: tokenInfo.token });

      await run('docker', [
        'run', '--rm',
        '--network', 'none',
        '--security-opt', 'no-new-privileges',
        '--cap-drop', 'ALL',
        '-v', `${volume}:${WORKSPACE_RUNTIME.directory}`,
        image,
        'sh', '-lc', `chmod 700 ${WORKSPACE_RUNTIME.directory}/.openchamber && chmod 600 ${RUNTIME_TOKEN_FILE}`,
      ], { timeoutMs: 300_000 });

      const args = [
        'run', '-d',
        '--name', container,
        ...runtimeLabels,
        '--security-opt', 'no-new-privileges',
        '--cap-drop', 'ALL',
        '-v', `${volume}:${WORKSPACE_RUNTIME.directory}`,
        '-w', WORKSPACE_RUNTIME.directory,
        '-e', `OPENCODE_AUTH_CONTENT=${env.OPENCODE_AUTH_CONTENT ?? ''}`,
        '-e', `OPENCODE_WORKSPACE_ID=${env.OPENCODE_WORKSPACE_ID ?? info.id}`,
        '-e', 'OPENCODE_EXPERIMENTAL_WORKSPACES=true',
      ];
      for (const [key, value] of Object.entries(runtimeEnvironment(meta, RUNTIME_TOKEN_FILE))) args.push('-e', `${key}=${value}`);
      if (policy.docker.memoryLimit) args.push('--memory', policy.docker.memoryLimit);
      if (policy.docker.cpuLimit) args.push('--cpus', policy.docker.cpuLimit);
      if (policy.docker.networkMode && policy.docker.networkMode !== 'default') args.push('--network', policy.docker.networkMode);
      args.push(image, 'sh', '-lc', runtimeCommand(RUNTIME_TOKEN_FILE));
      await run('docker', args, { timeoutMs: 120_000 });
      if (accessContainer) {
        await startAccessProxy({ image, accessContainer, runtimeContainer: container, labels: accessLabels, policy });
      }
      await health(info);
    } catch (error) {
      await remove(info).catch(() => undefined);
      throw error;
    }
  }

  async function target(info) {
    const meta = readExtra(info, provider);
    await verifyDockerWorkspace(info, meta);
    const token = await getWorkspaceToken(meta.auth.tokenRef);
    const port = await inspectPort(meta.runtime.accessContainer ?? meta.runtime.container);
    return {
      type: 'remote',
      url: `http://127.0.0.1:${port}`,
      headers: { [meta.auth.header]: token },
    };
  }

  async function health(info) {
    const remote = await target(info);
    await waitForHttpHealth(remote.url, remote.headers);
    return { ok: true };
  }

  async function remove(info) {
    const meta = readExtra(info, provider);
    await verifyDockerWorkspace(info, meta).catch((error) => {
      if (isDockerNotFound(error)) return false;
      throw error;
    });
    const failures = [];
    if (meta.runtime.accessContainer) {
      await run('docker', ['rm', '-f', meta.runtime.accessContainer], { timeoutMs: 60_000 }).catch((error) => {
        if (!isDockerNotFound(error)) failures.push(error);
      });
    }
    await run('docker', ['rm', '-f', meta.runtime.container], { timeoutMs: 60_000 }).catch((error) => {
      if (!isDockerNotFound(error)) failures.push(error);
    });
    const volumeExists = await verifyDockerVolume(info, meta).then(() => true).catch((error) => {
      if (isDockerNotFound(error)) return false;
      throw error;
    });
    if (!policy.retention.preserveOnDelete && volumeExists) {
      await run('docker', ['volume', 'rm', meta.storage.volume], { timeoutMs: 60_000 }).catch((error) => {
        if (!isDockerNotFound(error)) failures.push(error);
      });
    }
    if (failures.length > 0) throw new Error(`Docker workspace cleanup failed: ${failures.map((error) => error.message).join('; ')}`);
    await deleteWorkspaceToken(meta.auth.tokenRef).catch(() => undefined);
  }

  async function list(context) {
    if (!commandExists('docker')) throw new ProviderUnavailableError('Docker CLI is not available', { provider });
    const filters = ['--filter', 'label=openchamber.managed=true', '--filter', 'label=openchamber.workspace.provider=docker', '--filter', 'label=openchamber.workspace.role=runtime'];
    const projectID = context?.instance?.project?.id;
    if (projectID) filters.push('--filter', `label=openchamber.project.id=${projectID}`);
    const { stdout } = await run('docker', ['ps', '-a', ...filters, '--format', '{{json .}}'], { timeoutMs: 20_000 });
    return stdout.split('\n').filter(Boolean).map((line) => {
      const row = JSON.parse(line);
      const workspaceID = readDockerLabel(row.Labels, 'openchamber.workspace.id');
      const project = projectID ?? readDockerLabel(row.Labels, 'openchamber.project.id') ?? 'unknown';
      const id = workspaceID ?? row.Names ?? 'unknown';
      return {
        type: provider,
        name: row.Names ?? workspaceID ?? 'docker-workspace',
        branch: null,
        directory: WORKSPACE_RUNTIME.directory,
        extra: createExtra({ id, projectID: project }, provider, policy, {
          storage: { type: 'docker-volume', volume: `openchamber-ws-${sanitizeLabelValue(id)}` },
          runtime: { type: 'docker-container', container: row.Names, accessContainer: `${row.Names}-access` },
        }),
        projectID: project,
      };
    });
  }

  async function exportDiff(info) {
    const meta = readExtra(info, provider);
    await verifyDockerWorkspace(info, meta);
    const { stdout } = await run('docker', ['exec', meta.runtime.container, 'sh', '-lc', EXPORT_DIFF_COMMAND], { timeoutMs: 60_000 });
    return { patch: stdout, provider };
  }

  return { kind: provider, configure, create, target, remove, list, health, exportDiff };
}

async function startAccessProxy({ image, accessContainer, runtimeContainer, labels, policy }) {
  await run('docker', [
    'run', '-d',
    '--name', accessContainer,
    ...labels,
    '--security-opt', 'no-new-privileges',
    '--cap-drop', 'ALL',
    '-p', `127.0.0.1::${WORKSPACE_RUNTIME.port}`,
    '-e', `OPENCHAMBER_ACCESS_PROXY_TARGET=${runtimeContainer}`,
    image,
    'node', '-e', accessProxyScript(),
  ], { timeoutMs: 120_000 });
  if (policy.docker.networkMode && policy.docker.networkMode !== 'default') {
    await run('docker', ['network', 'connect', policy.docker.networkMode, accessContainer], { timeoutMs: 60_000 });
  }
}

function accessProxyScript() {
  return `
const net = require('node:net');
const target = process.env.OPENCHAMBER_ACCESS_PROXY_TARGET;
const port = ${WORKSPACE_RUNTIME.port};
if (!target) throw new Error('OPENCHAMBER_ACCESS_PROXY_TARGET is required');
net.createServer((socket) => {
  const upstream = net.connect(port, target, () => {
    upstream.setTimeout(0);
    socket.pipe(upstream).pipe(socket);
  });
  upstream.setTimeout(5000, () => {
    upstream.destroy();
    socket.destroy();
  });
  upstream.on('error', () => socket.destroy());
  socket.on('error', () => upstream.destroy());
}).listen(port, '0.0.0.0');
`;
}

async function ensureDockerNetwork(policy) {
  if (policy.docker.networkMode !== SECURE_DOCKER_NETWORK) return;
  const labels = {
    'openchamber.managed': 'true',
    'openchamber.workspace.provider': 'docker',
    'openchamber.workspace.network': 'secure',
  };
  const existing = await runJson('docker', ['network', 'inspect', SECURE_DOCKER_NETWORK], { timeoutMs: 20_000 }).catch((error) => {
    if (isDockerNotFound(error)) return null;
    throw error;
  });
  if (existing) {
    const network = existing?.[0];
    if (network?.Internal !== true) throw new Error(`Docker workspace network is not internal: ${SECURE_DOCKER_NETWORK}`);
    const existingLabels = network?.Labels ?? {};
    for (const [key, value] of Object.entries(labels)) {
      if (existingLabels[key] !== value) throw new Error(`Docker workspace network label mismatch for ${key}`);
    }
    return;
  }
  await run('docker', [
    'network', 'create', '--driver', 'bridge', '--internal',
    ...Object.entries(labels).flatMap(([key, value]) => ['--label', `${key}=${value}`]),
    SECURE_DOCKER_NETWORK,
  ], { timeoutMs: 60_000 });
}

async function verifyDockerWorkspace(info, meta) {
  requireDockerManagedLabels(info, meta);
  const inspected = await runJson('docker', ['inspect', meta.runtime.container], { timeoutMs: 20_000 });
  const labels = inspected?.[0]?.Config?.Labels ?? {};
  for (const [key, value] of Object.entries(meta.labels ?? {})) {
    if (labels[key] !== String(value)) throw new Error(`Docker workspace container label mismatch for ${key}`);
  }
}

async function verifyDockerVolume(info, meta) {
  requireDockerManagedLabels(info, meta);
  const inspected = await runJson('docker', ['volume', 'inspect', meta.storage.volume], { timeoutMs: 20_000 });
  const labels = inspected?.[0]?.Labels ?? {};
  for (const [key, value] of Object.entries(meta.labels ?? {})) {
    if (labels[key] !== String(value)) throw new Error(`Docker workspace volume label mismatch for ${key}`);
  }
}

function requireDockerManagedLabels(info, meta) {
  const labels = meta.labels ?? {};
  const required = {
    'openchamber.managed': 'true',
    'openchamber.workspace.provider': 'docker',
    'openchamber.workspace.id': canonicalWorkspaceLabelID(info.id),
  };
  for (const [key, value] of Object.entries(required)) {
    if (!value || labels[key] !== value) throw new Error(`Docker workspace metadata is missing required managed label: ${key}`);
  }
}

function isDockerNotFound(error) {
  const message = error instanceof Error ? error.message : String(error);
  return /No such object|No such container|No such volume|not found/i.test(message);
}

async function inspectPort(container) {
  const inspected = await runJson('docker', ['inspect', container], { timeoutMs: 20_000 });
  const entry = inspected?.[0];
  const running = entry?.State?.Running === true;
  if (!running) throw new Error(`Docker workspace container is not running: ${container}`);
  const ports = entry?.NetworkSettings?.Ports?.[`${WORKSPACE_RUNTIME.port}/tcp`];
  const port = Array.isArray(ports) ? ports[0]?.HostPort : undefined;
  if (!port) throw new Error(`Docker workspace has no localhost port mapping: ${container}`);
  return port;
}

function readDockerLabel(labels, key) {
  if (typeof labels !== 'string') return undefined;
  const item = labels.split(',').map((part) => part.trim()).find((part) => part.startsWith(`${key}=`));
  return item?.slice(key.length + 1);
}
