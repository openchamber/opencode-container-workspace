import { commandExists, run, runJson, sanitizeLabelValue } from '../process.js';
import { ProviderUnavailableError } from '../errors.js';
import { createExtra, readExtra, workspaceName, WORKSPACE_RUNTIME } from '../metadata.js';
import { createWorkspaceToken, deleteWorkspaceToken, getWorkspaceToken } from '../auth.js';
import { validateImage } from '../policy.js';
import { waitForHttpHealth } from '../health.js';

const EXPORT_DIFF_COMMAND = 'tmp=$(mktemp); idx=$(git rev-parse --git-path index 2>/dev/null || true); if [ -n "$idx" ] && [ -f "$idx" ]; then cp "$idx" "$tmp"; fi; GIT_INDEX_FILE="$tmp" git add -N . >/dev/null 2>&1 || true; GIT_INDEX_FILE="$tmp" git diff --binary HEAD; code=$?; rm -f "$tmp"; exit $code';

export function createDockerProvider({ policy, sourceDirectory }) {
  const provider = 'docker';

  async function preflight() {
    if (!commandExists('docker')) throw new ProviderUnavailableError('Docker CLI is not available', { provider });
    await run('docker', ['info'], { timeoutMs: 15_000 });
  }

  function configure(info) {
    const name = workspaceName(info, provider);
    const id = sanitizeLabelValue(info.id);
    const image = validateImage(policy, info.extra?.image ?? policy.defaultImage);
    const extra = createExtra({ ...info, id }, provider, { ...policy, defaultImage: image }, {
      storage: { type: 'docker-volume', volume: `openchamber-ws-${id}` },
      runtime: { type: 'docker-container', container: `openchamber-ws-${id}` },
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
    const labels = Object.entries(meta.labels).flatMap(([key, value]) => ['--label', `${key}=${value}`]);
    try {
      await run('docker', ['image', 'inspect', image], { timeoutMs: 20_000 }).catch(() => run('docker', ['pull', image], { timeoutMs: 300_000 }));
      await run('docker', ['volume', 'create', ...labels, volume]);
      await run('docker', [
        'run', '--rm',
        '-v', `${volume}:${WORKSPACE_RUNTIME.directory}`,
        '-v', `${sourceDirectory}:/source:ro`,
        image,
        'sh', '-lc', `cd /source && tar cf - . | tar xf - -C ${WORKSPACE_RUNTIME.directory}`,
      ], { timeoutMs: 300_000 });

      const args = [
        'run', '-d',
        '--name', container,
        ...labels,
        '-p', `127.0.0.1::${WORKSPACE_RUNTIME.port}`,
        '-v', `${volume}:${WORKSPACE_RUNTIME.directory}`,
        '-w', WORKSPACE_RUNTIME.directory,
        '-e', `OPENCODE_AUTH_CONTENT=${env.OPENCODE_AUTH_CONTENT ?? ''}`,
        '-e', `OPENCODE_WORKSPACE_ID=${env.OPENCODE_WORKSPACE_ID ?? info.id}`,
        '-e', 'OPENCODE_EXPERIMENTAL_WORKSPACES=true',
        '-e', `OPENCHAMBER_WORKSPACE_AUTH_HEADER=${meta.auth.header}`,
        '-e', `OPENCHAMBER_WORKSPACE_AUTH_TOKEN=${tokenInfo.token}`,
      ];
      if (policy.docker.memoryLimit) args.push('--memory', policy.docker.memoryLimit);
      if (policy.docker.cpuLimit) args.push('--cpus', policy.docker.cpuLimit);
      if (policy.docker.networkMode && policy.docker.networkMode !== 'default') args.push('--network', policy.docker.networkMode);
      args.push(image, 'sh', '-lc', `opencode serve --hostname 0.0.0.0 --port ${WORKSPACE_RUNTIME.port}`);
      await run('docker', args, { timeoutMs: 120_000 });
      await health(info);
    } catch (error) {
      await remove(info).catch(() => undefined);
      throw error;
    }
  }

  async function target(info) {
    const meta = readExtra(info, provider);
    const token = await getWorkspaceToken(meta.auth.tokenRef);
    const port = await inspectPort(meta.runtime.container);
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
    await run('docker', ['rm', '-f', meta.runtime.container], { timeoutMs: 60_000 }).catch(() => undefined);
    if (!policy.retention.preserveOnDelete) {
      await run('docker', ['volume', 'rm', meta.storage.volume], { timeoutMs: 60_000 }).catch(() => undefined);
    }
    await deleteWorkspaceToken(meta.auth.tokenRef).catch(() => undefined);
  }

  async function list(context) {
    if (!commandExists('docker')) return [];
    const filters = ['--filter', 'label=openchamber.managed=true', '--filter', 'label=openchamber.workspace.provider=docker'];
    const projectID = context?.instance?.project?.id;
    if (projectID) filters.push('--filter', `label=openchamber.project.id=${projectID}`);
    const { stdout } = await run('docker', ['ps', '-a', ...filters, '--format', '{{json .}}'], { timeoutMs: 20_000 }).catch(() => ({ stdout: '' }));
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
          runtime: { type: 'docker-container', container: row.Names },
        }),
        projectID: project,
      };
    });
  }

  async function exportDiff(info) {
    const meta = readExtra(info, provider);
    const { stdout } = await run('docker', ['exec', meta.runtime.container, 'sh', '-lc', EXPORT_DIFF_COMMAND], { timeoutMs: 60_000 });
    return { patch: stdout, provider };
  }

  return { kind: provider, configure, create, target, remove, list, health, exportDiff };
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
