import { createHash } from 'node:crypto';
import { canonicalWorkspaceLabelID } from '../label-id.js';
import { commandExists, run, runJson, sanitizeLabelValue } from '../process.js';
import { ProviderUnavailableError } from '../errors.js';
import { createExtra, readExtra, workspaceName, WORKSPACE_RUNTIME } from '../metadata.js';
import { createWorkspaceToken, deleteWorkspaceToken, getWorkspaceToken } from '../auth.js';
import { requireAppleContainerEgress, SECURE_APPLE_CONTAINER_NETWORK, validateImage } from '../policy.js';
import { waitForHttpHealth } from '../health.js';
import { BASELINE_COMMAND, RUNTIME_TOKEN_FILE, runtimeCommand, runtimeEnvironment } from '../runtime-command.js';

const EXPORT_DIFF_COMMAND = 'tmp=$(mktemp); idx=$(git rev-parse --git-path index 2>/dev/null || true); if [ -n "$idx" ] && [ -f "$idx" ]; then cp "$idx" "$tmp"; fi; GIT_INDEX_FILE="$tmp" git add -N . >/dev/null 2>&1 || true; GIT_INDEX_FILE="$tmp" git diff --binary HEAD; code=$?; rm -f "$tmp"; exit $code';

export function createAppleContainerProvider({ policy, sourceDirectory }) {
  const provider = 'apple-container';

  async function preflight() {
    requireAppleContainerEgress(policy);
    if (!commandExists(policy.appleContainer.cli)) throw new ProviderUnavailableError('Apple Container CLI is not available', { provider });
    await container(['system', 'status'], { timeoutMs: 15_000 });
  }

  function configure(info) {
    const id = canonicalWorkspaceLabelID(info.id);
    const image = validateImage(policy, info.extra?.image ?? policy.defaultImage);
    const name = workspaceName(info, provider);
    const extra = createExtra(info, provider, { ...policy, defaultImage: image }, {
      storage: { type: 'apple-container-volume', volume: `openchamber-ws-${id}` },
      runtime: {
        type: 'apple-container',
        container: `openchamber-ws-${id}`,
        network: policy.appleContainer.networkMode,
        hostPort: deterministicHostPort(id),
      },
    });
    return { ...info, name, directory: WORKSPACE_RUNTIME.directory, extra };
  }

  async function create(info, env) {
    await preflight();
    const meta = readExtra(info, provider);
    const image = validateImage(policy, meta.image);
    const tokenInfo = await createWorkspaceToken(info.id);
    const labels = Object.entries(meta.labels).flatMap(([key, value]) => ['--label', `${key}=${value}`]);
    try {
      await container(['image', 'inspect', image], { timeoutMs: 20_000 }).catch(() => container(['image', 'pull', image], { timeoutMs: 300_000 }));
      const network = await ensureAppleContainerNetwork(policy);
      await container(['volume', 'create', ...labels, meta.storage.volume], { timeoutMs: 60_000 });
      await container([
        'run', '-i', '--rm',
        '--network', 'none',
        '--cap-drop', 'ALL',
        '--volume', `${meta.storage.volume}:${WORKSPACE_RUNTIME.directory}`,
        '--mount', `type=bind,source=${sourceDirectory},target=/source,readonly`,
        image,
        'sh', '-lc', `cd /source && tar cf - . | tar xf - -C ${WORKSPACE_RUNTIME.directory} && ${BASELINE_COMMAND} && umask 077 && mkdir -p ${WORKSPACE_RUNTIME.directory}/.openchamber && cat > ${RUNTIME_TOKEN_FILE}`,
      ], { timeoutMs: 300_000, input: tokenInfo.token });

      await container([
        'run', '--rm',
        '--network', 'none',
        '--cap-drop', 'ALL',
        '--volume', `${meta.storage.volume}:${WORKSPACE_RUNTIME.directory}`,
        image,
        'sh', '-lc', `chmod 700 ${WORKSPACE_RUNTIME.directory}/.openchamber && chmod 600 ${RUNTIME_TOKEN_FILE}`,
      ], { timeoutMs: 300_000 });

      const args = [
        'run', '--detach',
        '--name', meta.runtime.container,
        ...labels,
        '--network', meta.runtime.network,
        '--cap-drop', 'ALL',
        '--publish', `127.0.0.1:${meta.runtime.hostPort}:${WORKSPACE_RUNTIME.port}`,
        '--volume', `${meta.storage.volume}:${WORKSPACE_RUNTIME.directory}`,
        '--workdir', WORKSPACE_RUNTIME.directory,
        '--env', `OPENCODE_AUTH_CONTENT=${env.OPENCODE_AUTH_CONTENT ?? ''}`,
        '--env', `OPENCODE_WORKSPACE_ID=${env.OPENCODE_WORKSPACE_ID ?? info.id}`,
        '--env', 'OPENCODE_EXPERIMENTAL_WORKSPACES=true',
      ];
      for (const [key, value] of Object.entries(runtimeEnvironment(withAppleContainerProxy(meta, network), RUNTIME_TOKEN_FILE))) args.push('--env', `${key}=${value}`);
      if (policy.appleContainer.memoryLimit) args.push('--memory', policy.appleContainer.memoryLimit);
      if (policy.appleContainer.cpuLimit) args.push('--cpus', policy.appleContainer.cpuLimit);
      args.push(image, 'sh', '-lc', runtimeCommand(RUNTIME_TOKEN_FILE));
      await container(args, { timeoutMs: 120_000 });
      await health(info);
    } catch (error) {
      await remove(info).catch(() => undefined);
      throw error;
    }
  }

  async function target(info) {
    const meta = readExtra(info, provider);
    await verifyAppleContainerWorkspace(info, meta);
    const token = await getWorkspaceToken(meta.auth.tokenRef);
    const port = await inspectPort(meta.runtime.container, containerJson);
    return {
      type: 'remote',
      url: `http://127.0.0.1:${port}`,
      headers: { [meta.auth.header]: token },
    };
  }

  async function health(info) {
    const remote = await target(info);
    await waitForHttpHealth(remote.url, remote.headers, { timeoutMs: 90_000 });
    return { ok: true };
  }

  async function remove(info) {
    const meta = readExtra(info, provider);
    await verifyAppleContainerWorkspace(info, meta).catch((error) => {
      if (!isAppleContainerNotFound(error)) throw error;
    });
    const failures = [];
    await container(['stop', meta.runtime.container], { timeoutMs: 60_000 }).catch((error) => {
      if (!isAppleContainerNotFound(error)) failures.push(error);
    });
    await container(['delete', '--force', meta.runtime.container], { timeoutMs: 60_000 }).catch((error) => {
      if (!isAppleContainerNotFound(error)) failures.push(error);
    });
    const volumeExists = await verifyAppleContainerVolume(info, meta).then(() => true).catch((error) => {
      if (isAppleContainerNotFound(error)) return false;
      throw error;
    });
    if (!policy.retention.preserveOnDelete && volumeExists) {
      await container(['volume', 'delete', meta.storage.volume], { timeoutMs: 60_000 }).catch((error) => {
        if (!isAppleContainerNotFound(error)) failures.push(error);
      });
    }
    if (failures.length > 0) throw new Error(`Apple Container workspace cleanup failed: ${failures.map((error) => error.message).join('; ')}`);
    await deleteWorkspaceToken(meta.auth.tokenRef).catch(() => undefined);
  }

  async function list(context) {
    if (!commandExists(policy.appleContainer.cli)) throw new ProviderUnavailableError('Apple Container CLI is not available', { provider });
    const projectID = context?.instance?.project?.id;
    const { stdout } = await container(['list', '--all', '--format', 'json'], { timeoutMs: 20_000 });
    const rows = stdout.trim() ? JSON.parse(stdout) : [];
    return rows.filter((row) => {
      const labels = row.configuration?.labels ?? {};
      return labels['openchamber.managed'] === 'true'
        && labels['openchamber.workspace.provider'] === provider
        && (!projectID || labels['openchamber.project.id'] === projectID);
    }).map((row) => {
      const labels = row.configuration?.labels ?? {};
      const id = labels['openchamber.workspace.id'] ?? row.id ?? 'unknown';
      const project = labels['openchamber.project.id'] ?? projectID ?? 'unknown';
      const hostPort = row.configuration?.publishedPorts?.find((port) => port.containerPort === WORKSPACE_RUNTIME.port)?.hostPort;
      return {
        type: provider,
        name: row.id ?? id,
        branch: null,
        directory: WORKSPACE_RUNTIME.directory,
        extra: createExtra({ id, projectID: project }, provider, policy, {
          storage: { type: 'apple-container-volume', volume: `openchamber-ws-${sanitizeLabelValue(id)}` },
          runtime: {
            type: 'apple-container',
            container: row.id,
            network: policy.appleContainer.networkMode,
            hostPort: hostPort ?? deterministicHostPort(id),
          },
        }),
        projectID: project,
      };
    });
  }

  async function exportDiff(info) {
    const meta = readExtra(info, provider);
    await verifyAppleContainerWorkspace(info, meta);
    const { stdout } = await container(['exec', meta.runtime.container, 'sh', '-lc', EXPORT_DIFF_COMMAND], { timeoutMs: 60_000 });
    return { patch: stdout, provider };
  }

  function container(args, options = {}) {
    return run(policy.appleContainer.cli, args, options);
  }

  function containerJson(args, options = {}) {
    return runJson(policy.appleContainer.cli, args, options);
  }

  return { kind: provider, configure, create, target, remove, list, health, exportDiff };

  async function ensureAppleContainerNetwork(currentPolicy) {
    if (currentPolicy.appleContainer.networkMode !== SECURE_APPLE_CONTAINER_NETWORK) {
      return inspectAppleContainerNetwork(currentPolicy.appleContainer.networkMode);
    }
    const labels = {
      'openchamber.managed': 'true',
      'openchamber.workspace.provider': provider,
      'openchamber.workspace.network': 'secure',
    };
    const existing = await containerJson(['network', 'inspect', SECURE_APPLE_CONTAINER_NETWORK], { timeoutMs: 20_000 }).catch((error) => {
      if (isAppleContainerNotFound(error)) return null;
      throw error;
    });
    if (existing) {
      const network = existing?.[0];
      if (network?.configuration?.mode !== 'hostOnly') throw new Error(`Apple Container workspace network is not host-only: ${SECURE_APPLE_CONTAINER_NETWORK}`);
      const existingLabels = network?.configuration?.labels ?? {};
      for (const [key, value] of Object.entries(labels)) {
        if (existingLabels[key] !== value) throw new Error(`Apple Container workspace network label mismatch for ${key}`);
      }
      return network;
    }
    await container([
      'network', 'create', '--internal',
      ...Object.entries(labels).flatMap(([key, value]) => ['--label', `${key}=${value}`]),
      SECURE_APPLE_CONTAINER_NETWORK,
    ], { timeoutMs: 60_000 });
    return inspectAppleContainerNetwork(SECURE_APPLE_CONTAINER_NETWORK);
  }

  async function inspectAppleContainerNetwork(network) {
    const inspected = await containerJson(['network', 'inspect', network], { timeoutMs: 20_000 });
    return inspected?.[0];
  }

  async function verifyAppleContainerWorkspace(info, meta) {
    requireAppleContainerManagedLabels(info, meta);
    const inspected = await containerJson(['inspect', meta.runtime.container], { timeoutMs: 20_000 });
    const entry = inspected?.[0];
    const labels = entry?.configuration?.labels ?? {};
    for (const [key, value] of Object.entries(meta.labels ?? {})) {
      if (labels[key] !== String(value)) throw new Error(`Apple Container workspace label mismatch for ${key}`);
    }
  }

  async function verifyAppleContainerVolume(info, meta) {
    requireAppleContainerManagedLabels(info, meta);
    const inspected = await containerJson(['volume', 'inspect', meta.storage.volume], { timeoutMs: 20_000 });
    const labels = inspected?.[0]?.configuration?.labels ?? inspected?.[0]?.labels ?? {};
    for (const [key, value] of Object.entries(meta.labels ?? {})) {
      if (labels[key] !== String(value)) throw new Error(`Apple Container workspace volume label mismatch for ${key}`);
    }
  }
}

function requireAppleContainerManagedLabels(info, meta) {
  const labels = meta.labels ?? {};
  const required = {
    'openchamber.managed': 'true',
    'openchamber.workspace.provider': 'apple-container',
    'openchamber.workspace.id': canonicalWorkspaceLabelID(info.id),
  };
  for (const [key, value] of Object.entries(required)) {
    if (!value || labels[key] !== value) throw new Error(`Apple Container workspace metadata is missing required managed label: ${key}`);
  }
}

function inspectPortFromEntry(entry) {
  if (entry?.status?.state !== 'running') throw new Error(`Apple Container workspace is not running: ${entry?.id ?? '<unknown>'}`);
  const port = entry?.configuration?.publishedPorts?.find((item) => item.containerPort === WORKSPACE_RUNTIME.port && item.hostAddress === '127.0.0.1')?.hostPort;
  if (!port) throw new Error(`Apple Container workspace has no localhost port mapping: ${entry?.id ?? '<unknown>'}`);
  return port;
}

async function inspectPort(container, containerJson) {
  const inspected = await containerJson(['inspect', container], { timeoutMs: 20_000 });
  return inspectPortFromEntry(inspected?.[0]);
}

function deterministicHostPort(id) {
  const digest = createHash('sha256').update(id).digest();
  return 49152 + digest.readUInt16BE(0) % 16384;
}

function withAppleContainerProxy(meta, network) {
  const proxy = meta.policy?.egress?.httpProxy;
  const gateway = network?.status?.ipv4Gateway;
  if (!proxy || !gateway) return meta;
  const parsed = new URL(proxy);
  if (parsed.hostname !== '127.0.0.1' && parsed.hostname !== 'localhost') return meta;
  parsed.hostname = gateway;
  return {
    ...meta,
    policy: {
      ...meta.policy,
      egress: { ...meta.policy.egress, httpProxy: parsed.toString() },
    },
  };
}

function isAppleContainerNotFound(error) {
  const message = error instanceof Error ? error.message : String(error);
  return /not found|no such container|no such volume|does not exist/i.test(message);
}
