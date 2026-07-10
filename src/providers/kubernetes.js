import { createHash } from 'node:crypto';
import { createServer } from 'node:net';
import { commandExists, run, spawnBackground, sanitizeLabelValue } from '../process.js';
import { ProviderUnavailableError } from '../errors.js';
import { createExtra, readExtra, workspaceName, WORKSPACE_RUNTIME } from '../metadata.js';
import { createWorkspaceToken, deleteWorkspaceToken, getWorkspaceToken } from '../auth.js';
import { validateImage } from '../policy.js';
import { waitForHttpHealth } from '../health.js';

const EXPORT_DIFF_COMMAND = 'tmp=$(mktemp); idx=$(git rev-parse --git-path index 2>/dev/null || true); if [ -n "$idx" ] && [ -f "$idx" ]; then cp "$idx" "$tmp"; fi; GIT_INDEX_FILE="$tmp" git add -N . >/dev/null 2>&1 || true; GIT_INDEX_FILE="$tmp" git diff --binary HEAD; code=$?; rm -f "$tmp"; exit $code';

export function createKubernetesProvider({ policy, sourceDirectory }) {
  const provider = 'kubernetes';

  async function kubectl(args, options = {}) {
    const base = [];
    if (policy.kubernetes.context) base.push('--context', policy.kubernetes.context);
    return run('kubectl', [...base, ...args], options);
  }

  async function preflight() {
    if (!commandExists('kubectl')) throw new ProviderUnavailableError('kubectl is not available', { provider });
    for (const [verb, resource] of requiredKubernetesPermissions(policy)) {
      await kubectl(['auth', 'can-i', verb, resource, '-n', policy.kubernetes.namespace], { timeoutMs: 20_000 });
    }
  }

  function configure(info) {
    const id = sanitizeLabelValue(info.id);
    const image = validateImage(policy, info.extra?.image ?? policy.defaultImage);
    const name = workspaceName(info, provider);
    const resourceName = kubernetesResourceName('openchamber-ws', info.id);
    const extra = createExtra({ ...info, id }, provider, { ...policy, defaultImage: image }, {
      storage: { type: 'kubernetes-pvc', namespace: policy.kubernetes.namespace, pvc: resourceName },
      runtime: {
        type: 'kubernetes-deployment',
        namespace: policy.kubernetes.namespace,
        deployment: resourceName,
        service: resourceName,
        secret: kubernetesResourceName(`${resourceName}-auth`, info.id),
        connectivity: policy.kubernetes.connectivity,
      },
    });
    return { ...info, name, directory: WORKSPACE_RUNTIME.directory, extra };
  }

  async function create(info, env) {
    await preflight();
    const meta = readExtra(info, provider);
    const image = validateImage(policy, meta.image);
    const tokenInfo = await createWorkspaceToken(info.id);
    try {
      await applyManifest(buildManifest(meta, image, tokenInfo.token, env));
      await kubectl(['rollout', 'status', `deployment/${meta.runtime.deployment}`, '-n', meta.runtime.namespace, '--timeout=120s'], { timeoutMs: 150_000 });
      await seedWorkspace(meta, sourceDirectory, policy);
      await kubectl(['rollout', 'restart', `deployment/${meta.runtime.deployment}`, '-n', meta.runtime.namespace], { timeoutMs: 60_000 });
      await kubectl(['rollout', 'status', `deployment/${meta.runtime.deployment}`, '-n', meta.runtime.namespace, '--timeout=120s'], { timeoutMs: 150_000 });
      await health(info);
    } catch (error) {
      await remove(info).catch(() => undefined);
      throw error;
    }
  }

  async function target(info) {
    const meta = readExtra(info, provider);
    const token = await getWorkspaceToken(meta.auth.tokenRef);
    if (meta.runtime.connectivity === 'ingress' && policy.kubernetes.ingressBaseUrl) {
      return {
        type: 'remote',
        url: `${policy.kubernetes.ingressBaseUrl.replace(/\/$/, '')}/${meta.runtime.service}`,
        headers: { [meta.auth.header]: token },
      };
    }
    const port = await ensurePortForward(meta);
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
    stopPortForward(portForwardKey(meta));
    await kubectl(['delete', 'deployment', meta.runtime.deployment, '-n', meta.runtime.namespace, '--ignore-not-found=true'], { timeoutMs: 60_000 }).catch(() => undefined);
    await kubectl(['delete', 'service', meta.runtime.service, '-n', meta.runtime.namespace, '--ignore-not-found=true'], { timeoutMs: 60_000 }).catch(() => undefined);
    await kubectl(['delete', 'secret', meta.runtime.secret, '-n', meta.runtime.namespace, '--ignore-not-found=true'], { timeoutMs: 60_000 }).catch(() => undefined);
    if (!policy.retention.preserveOnDelete) {
      await kubectl(['delete', 'pvc', meta.storage.pvc, '-n', meta.storage.namespace, '--ignore-not-found=true'], { timeoutMs: 60_000 }).catch(() => undefined);
    }
    await deleteWorkspaceToken(meta.auth.tokenRef).catch(() => undefined);
  }

  async function list(context) {
    if (!commandExists('kubectl')) return [];
    const projectID = sanitizeLabelValue(context?.instance?.project?.id ?? '');
    const selector = projectID
      ? `openchamber.io/managed=true,openchamber.io/provider=kubernetes,openchamber.io/project-id=${projectID}`
      : 'openchamber.io/managed=true,openchamber.io/provider=kubernetes';
    const { stdout } = await kubectl(['get', 'deployment', '-n', policy.kubernetes.namespace, '-l', selector, '-o', 'json'], { timeoutMs: 30_000 }).catch(() => ({ stdout: '{"items":[]}' }));
    const parsed = JSON.parse(stdout);
    return (parsed.items ?? []).map((item) => {
      const labels = item.metadata?.labels ?? {};
      const id = labels['openchamber.io/workspace-id'] ?? item.metadata?.name ?? 'unknown';
      const project = labels['openchamber.io/project-id'] ?? context?.instance?.project?.id ?? 'unknown';
      const deployment = item.metadata?.name ?? `openchamber-ws-${id}`.slice(0, 63);
      return {
        type: provider,
        name: deployment,
        branch: null,
        directory: WORKSPACE_RUNTIME.directory,
        extra: createExtra({ id, projectID: project }, provider, policy, {
          storage: { type: 'kubernetes-pvc', namespace: policy.kubernetes.namespace, pvc: deployment },
          runtime: {
            type: 'kubernetes-deployment',
            namespace: policy.kubernetes.namespace,
            deployment,
            service: deployment,
            secret: kubernetesResourceName(`${deployment}-auth`, id),
            connectivity: policy.kubernetes.connectivity,
          },
        }),
        projectID: project,
      };
    });
  }

  async function exportDiff(info) {
    const meta = readExtra(info, provider);
    const { stdout } = await kubectl(['exec', `deployment/${meta.runtime.deployment}`, '-n', meta.runtime.namespace, '--', 'sh', '-lc', EXPORT_DIFF_COMMAND], { timeoutMs: 60_000 });
    return { patch: stdout, provider };
  }

  return { kind: provider, configure, create, target, remove, list, health, exportDiff };

  async function applyManifest(manifest) {
    await run('kubectl', [
      ...(policy.kubernetes.context ? ['--context', policy.kubernetes.context] : []),
      'apply', '-f', '-',
    ], { timeoutMs: 60_000, env: { KUBECTL_EXTERNAL_DIFF: 'true' }, input: manifest });
  }
}

function buildManifest(meta, image, token, env) {
  const labels = meta.labels;
  const namespace = meta.runtime.namespace;
  const envBlock = [
    { name: 'OPENCODE_AUTH_CONTENT', value: env.OPENCODE_AUTH_CONTENT ?? '' },
    { name: 'OPENCODE_WORKSPACE_ID', value: env.OPENCODE_WORKSPACE_ID ?? labels['openchamber.io/workspace-id'] },
    { name: 'OPENCODE_EXPERIMENTAL_WORKSPACES', value: 'true' },
    { name: 'OPENCHAMBER_WORKSPACE_AUTH_HEADER', value: meta.auth.header },
    { name: 'OPENCHAMBER_WORKSPACE_AUTH_TOKEN', valueFrom: { secretKeyRef: { name: meta.runtime.secret, key: 'token' } } },
  ];
  return JSON.stringify({
    apiVersion: 'v1',
    kind: 'List',
    items: [
      {
        apiVersion: 'v1', kind: 'Secret', metadata: { name: meta.runtime.secret, namespace, labels }, type: 'Opaque',
        stringData: { token },
      },
      {
        apiVersion: 'v1', kind: 'PersistentVolumeClaim', metadata: { name: meta.storage.pvc, namespace, labels },
        spec: { accessModes: ['ReadWriteOnce'], resources: { requests: { storage: meta.policy.kubernetes.storage } } },
      },
      {
        apiVersion: 'apps/v1', kind: 'Deployment', metadata: { name: meta.runtime.deployment, namespace, labels },
        spec: {
          replicas: 1,
          selector: { matchLabels: { 'openchamber.io/workspace-id': labels['openchamber.io/workspace-id'] } },
          template: {
            metadata: { labels },
            spec: {
              containers: [{
                name: 'opencode', image, workingDir: WORKSPACE_RUNTIME.directory,
                command: ['sh', '-lc', `opencode serve --hostname 0.0.0.0 --port ${WORKSPACE_RUNTIME.port}`],
                ports: [{ containerPort: WORKSPACE_RUNTIME.port }], env: envBlock,
                resources: {
                  requests: { cpu: meta.policy.kubernetes.cpuRequest, memory: meta.policy.kubernetes.memoryRequest },
                  limits: { cpu: meta.policy.kubernetes.cpuLimit, memory: meta.policy.kubernetes.memoryLimit },
                },
                volumeMounts: [{ name: 'workspace', mountPath: WORKSPACE_RUNTIME.directory }],
              }],
              volumes: [{ name: 'workspace', persistentVolumeClaim: { claimName: meta.storage.pvc } }],
            },
          },
        },
      },
      {
        apiVersion: 'v1', kind: 'Service', metadata: { name: meta.runtime.service, namespace, labels },
        spec: { selector: { 'openchamber.io/workspace-id': labels['openchamber.io/workspace-id'] }, ports: [{ port: WORKSPACE_RUNTIME.port, targetPort: WORKSPACE_RUNTIME.port }] },
      },
    ],
  });
}

async function seedWorkspace(meta, sourceDirectory, policy) {
  // Kubernetes seeding intentionally uses `kubectl cp` after the pod is ready so
  // the runtime never gets a writeable host mount. For git projects, the copied
  // repository keeps its own baseline and later `git diff --binary` export works.
  const pod = await findWorkspacePod(meta, policy);
  await run('kubectl', [
    ...(policy.kubernetes.context ? ['--context', policy.kubernetes.context] : []),
    'cp', '.', `${meta.runtime.namespace}/${pod}:${WORKSPACE_RUNTIME.directory}`,
  ], {
    cwd: sourceDirectory,
    timeoutMs: 300_000,
  });
}

async function findWorkspacePod(meta, policy) {
  const selector = `openchamber.io/workspace-id=${meta.labels['openchamber.io/workspace-id']}`;
  const { stdout } = await run('kubectl', [
    ...(policy.kubernetes.context ? ['--context', policy.kubernetes.context] : []),
    'get', 'pods', '-n', meta.runtime.namespace, '-l', selector, '-o', 'json',
  ], { timeoutMs: 30_000 });
  const pods = JSON.parse(stdout).items ?? [];
  const ready = pods.find((pod) => pod.status?.phase === 'Running' && (pod.status?.containerStatuses ?? []).every((status) => status.ready));
  const name = ready?.metadata?.name ?? pods[0]?.metadata?.name;
  if (!name) throw new Error(`No Kubernetes workspace pod found for ${meta.runtime.deployment}`);
  return name;
}

async function ensurePortForward(meta) {
  const key = portForwardKey(meta);
  const existing = portForwardState.get(key);
  if (existing && existing.child.exitCode === null && existing.child.signalCode === null) {
    return existing.port;
  }
  stopPortForward(key);
  const port = await getFreeLocalPort();
  const args = [
    ...(meta.policy.kubernetes.context ? ['--context', meta.policy.kubernetes.context] : []),
    'port-forward', `service/${meta.runtime.service}`, `${port}:${WORKSPACE_RUNTIME.port}`, '-n', meta.runtime.namespace,
  ];
  const child = spawnBackground('kubectl', args);
  portForwardState.set(key, { child, port });
  await new Promise((resolve) => setTimeout(resolve, 1000));
  if (child.exitCode !== null || child.signalCode !== null) {
    portForwardState.delete(key);
    throw new Error(`Kubernetes port-forward failed for ${meta.runtime.service}`);
  }
  return port;
}

const portForwardState = new Map();

function portForwardKey(meta) {
  return `${meta.policy.kubernetes.context ?? ''}:${meta.runtime.namespace}:${meta.runtime.service}`;
}

function stopPortForward(key) {
  const existing = portForwardState.get(key);
  if (!existing) return;
  existing.child.kill('SIGTERM');
  portForwardState.delete(key);
}

function getFreeLocalPort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      const port = typeof address === 'object' && address ? address.port : null;
      server.close(() => {
        if (port) resolve(port);
        else reject(new Error('Failed to allocate a localhost port'));
      });
    });
  });
}

function kubernetesResourceName(prefix, value) {
  const hash = createHash('sha256').update(String(value ?? '')).digest('hex').slice(0, 10);
  const cleaned = String(value ?? '')
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, '-')
    .replace(/^-+|-+$/g, '')
    .replace(/-{2,}/g, '-') || 'workspace';
  const base = `${prefix}-${cleaned}`.replace(/^-+|-+$/g, '');
  return `${base.slice(0, Math.max(1, 63 - hash.length - 1)).replace(/-+$/g, '')}-${hash}`;
}

function requiredKubernetesPermissions(policy) {
  const permissions = [
    ['get', 'pods'],
    ['list', 'pods'],
    ['watch', 'pods'],
    ['create', 'pods/exec'],
    ['create', 'pods/portforward'],
    ['create', 'secrets'],
    ['get', 'secrets'],
    ['patch', 'secrets'],
    ['delete', 'secrets'],
    ['create', 'persistentvolumeclaims'],
    ['get', 'persistentvolumeclaims'],
    ['patch', 'persistentvolumeclaims'],
    ['delete', 'persistentvolumeclaims'],
    ['create', 'deployments.apps'],
    ['get', 'deployments.apps'],
    ['patch', 'deployments.apps'],
    ['delete', 'deployments.apps'],
    ['create', 'services'],
    ['get', 'services'],
    ['patch', 'services'],
    ['delete', 'services'],
  ];
  return permissions;
}
