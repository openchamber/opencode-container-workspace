import { PolicyError } from './errors.js';

const DEFAULT_IMAGE = 'ghcr.io/openchamber/opencode-workspace:1.0.0';

export function readPolicy(options = {}) {
  const env = process.env;
  const allowedImages = splitList(options.allowedImages ?? env.OPENCHAMBER_WORKSPACE_ALLOWED_IMAGES);
  const defaultImage = String(options.defaultImage ?? env.OPENCHAMBER_WORKSPACE_IMAGE ?? DEFAULT_IMAGE);
  const rawDefaultProvider = options.defaultProvider ?? env.OPENCHAMBER_WORKSPACE_DEFAULT_PROVIDER;
  const defaultProvider = rawDefaultProvider === 'kubernetes'
    ? 'kubernetes'
    : 'docker';
  return {
    allowedImages,
    defaultProvider,
    requirePinnedImage: bool(options.requirePinnedImage ?? env.OPENCHAMBER_WORKSPACE_REQUIRE_PINNED_IMAGE, true),
    defaultImage,
    docker: {
      networkMode: options.docker?.networkMode ?? env.OPENCHAMBER_WORKSPACE_DOCKER_NETWORK ?? 'default',
      memoryLimit: options.docker?.memoryLimit ?? env.OPENCHAMBER_WORKSPACE_DOCKER_MEMORY,
      cpuLimit: options.docker?.cpuLimit ?? env.OPENCHAMBER_WORKSPACE_DOCKER_CPUS,
    },
    kubernetes: {
      context: options.kubernetes?.context ?? env.OPENCHAMBER_WORKSPACE_KUBE_CONTEXT,
      namespace: options.kubernetes?.namespace ?? env.OPENCHAMBER_WORKSPACE_KUBE_NAMESPACE ?? 'openchamber-workspaces',
      connectivity: options.kubernetes?.connectivity ?? env.OPENCHAMBER_WORKSPACE_KUBE_CONNECTIVITY ?? 'port-forward',
      ingressBaseUrl: options.kubernetes?.ingressBaseUrl ?? env.OPENCHAMBER_WORKSPACE_KUBE_INGRESS_BASE_URL,
      storage: options.kubernetes?.storage ?? env.OPENCHAMBER_WORKSPACE_KUBE_STORAGE ?? '8Gi',
      cpuRequest: options.kubernetes?.cpuRequest ?? env.OPENCHAMBER_WORKSPACE_KUBE_CPU_REQUEST ?? '250m',
      memoryRequest: options.kubernetes?.memoryRequest ?? env.OPENCHAMBER_WORKSPACE_KUBE_MEMORY_REQUEST ?? '512Mi',
      cpuLimit: options.kubernetes?.cpuLimit ?? env.OPENCHAMBER_WORKSPACE_KUBE_CPU_LIMIT ?? '2',
      memoryLimit: options.kubernetes?.memoryLimit ?? env.OPENCHAMBER_WORKSPACE_KUBE_MEMORY_LIMIT ?? '4Gi',
      networkPolicy: options.kubernetes?.networkPolicy ?? env.OPENCHAMBER_WORKSPACE_KUBE_NETWORK_POLICY ?? 'default',
    },
    retention: {
      ttlHours: number(options.retention?.ttlHours ?? env.OPENCHAMBER_WORKSPACE_TTL_HOURS),
      preserveOnDelete: bool(options.retention?.preserveOnDelete ?? env.OPENCHAMBER_WORKSPACE_PRESERVE_ON_DELETE, false),
    },
    secrets: {
      mode: options.secrets?.mode ?? env.OPENCHAMBER_WORKSPACE_SECRET_MODE ?? 'file',
    },
  };
}

export function validateImage(policy, image) {
  const normalized = String(image ?? '').trim();
  if (!normalized) throw new PolicyError('Workspace image is required');
  if (policy.requirePinnedImage && !isPinnedImage(normalized)) {
    throw new PolicyError(`Workspace image must be pinned by digest or explicit non-latest tag: ${normalized}`);
  }
  if (policy.allowedImages.length > 0 && !policy.allowedImages.some((allowed) => imageMatches(allowed, normalized))) {
    throw new PolicyError(`Workspace image is not allowed by policy: ${normalized}`);
  }
  return normalized;
}

function splitList(value) {
  if (Array.isArray(value)) return value.map(String).filter(Boolean);
  if (typeof value !== 'string') return [];
  return value.split(',').map((item) => item.trim()).filter(Boolean);
}

function bool(value, fallback) {
  if (typeof value === 'boolean') return value;
  if (typeof value !== 'string') return fallback;
  if (/^(1|true|yes)$/i.test(value)) return true;
  if (/^(0|false|no)$/i.test(value)) return false;
  return fallback;
}

function number(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value !== 'string' || !value.trim()) return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function isPinnedImage(image) {
  if (image.includes('@sha256:')) return true;
  const lastSegment = image.split('/').at(-1) ?? image;
  const tag = lastSegment.includes(':') ? lastSegment.split(':').at(-1) : '';
  return Boolean(tag && tag !== 'latest');
}

function imageMatches(pattern, image) {
  if (pattern === image) return true;
  if (pattern.endsWith('*')) return image.startsWith(pattern.slice(0, -1));
  return false;
}
