import { PolicyError } from './errors.js';
import { isIP } from 'node:net';

const DEFAULT_IMAGE = 'ghcr.io/openchamber/opencode-workspace:1.0.0';
export const SECURE_DOCKER_NETWORK = 'openchamber-secure-workspaces';
export const SECURE_APPLE_CONTAINER_NETWORK = 'openchamber-secure-workspaces-apple';

export function readPolicy(options = {}) {
  const env = process.env;
  const allowedImages = splitList(options.allowedImages ?? env.OPENCHAMBER_WORKSPACE_ALLOWED_IMAGES);
  const defaultImage = String(options.defaultImage ?? env.OPENCHAMBER_WORKSPACE_IMAGE ?? DEFAULT_IMAGE);
  const rawDefaultProvider = options.defaultProvider ?? env.OPENCHAMBER_WORKSPACE_DEFAULT_PROVIDER;
  const defaultProvider = rawDefaultProvider === 'kubernetes'
    ? 'kubernetes'
    : rawDefaultProvider === 'apple-container'
      ? 'apple-container'
    : 'docker';
  const dockerAllowedNetworks = splitList(options.docker?.allowedNetworks ?? env.OPENCHAMBER_WORKSPACE_DOCKER_ALLOWED_NETWORKS);
  const dockerNetworkMode = normalizeDockerNetworkMode(options.docker?.networkMode ?? env.OPENCHAMBER_WORKSPACE_DOCKER_NETWORK ?? SECURE_DOCKER_NETWORK);
  validateDockerNetworkMode(dockerNetworkMode, dockerAllowedNetworks);
  const kubernetesNamespace = String(options.kubernetes?.namespace ?? env.OPENCHAMBER_WORKSPACE_KUBE_NAMESPACE ?? 'openchamber-workspaces');
  const kubernetesContext = options.kubernetes?.context ?? env.OPENCHAMBER_WORKSPACE_KUBE_CONTEXT;
  validateAllowedValue('Kubernetes context', kubernetesContext, splitList(options.kubernetes?.allowedContexts ?? env.OPENCHAMBER_WORKSPACE_KUBE_ALLOWED_CONTEXTS));
  validateAllowedValue('Kubernetes namespace', kubernetesNamespace, splitList(options.kubernetes?.allowedNamespaces ?? env.OPENCHAMBER_WORKSPACE_KUBE_ALLOWED_NAMESPACES));

  return {
    allowedImages,
    defaultProvider,
    requirePinnedImage: bool(options.requirePinnedImage ?? env.OPENCHAMBER_WORKSPACE_REQUIRE_PINNED_IMAGE, true),
    defaultImage,
    docker: {
      networkMode: dockerNetworkMode,
      allowedNetworks: dockerAllowedNetworks,
      memoryLimit: options.docker?.memoryLimit ?? env.OPENCHAMBER_WORKSPACE_DOCKER_MEMORY,
      cpuLimit: options.docker?.cpuLimit ?? env.OPENCHAMBER_WORKSPACE_DOCKER_CPUS,
    },
    kubernetes: {
      context: kubernetesContext,
      namespace: kubernetesNamespace,
      allowedContexts: splitList(options.kubernetes?.allowedContexts ?? env.OPENCHAMBER_WORKSPACE_KUBE_ALLOWED_CONTEXTS),
      allowedNamespaces: splitList(options.kubernetes?.allowedNamespaces ?? env.OPENCHAMBER_WORKSPACE_KUBE_ALLOWED_NAMESPACES),
      connectivity: options.kubernetes?.connectivity ?? env.OPENCHAMBER_WORKSPACE_KUBE_CONNECTIVITY ?? 'port-forward',
      ingressBaseUrl: options.kubernetes?.ingressBaseUrl ?? env.OPENCHAMBER_WORKSPACE_KUBE_INGRESS_BASE_URL,
      storage: options.kubernetes?.storage ?? env.OPENCHAMBER_WORKSPACE_KUBE_STORAGE ?? '8Gi',
      cpuRequest: options.kubernetes?.cpuRequest ?? env.OPENCHAMBER_WORKSPACE_KUBE_CPU_REQUEST ?? '250m',
      memoryRequest: options.kubernetes?.memoryRequest ?? env.OPENCHAMBER_WORKSPACE_KUBE_MEMORY_REQUEST ?? '512Mi',
      cpuLimit: options.kubernetes?.cpuLimit ?? env.OPENCHAMBER_WORKSPACE_KUBE_CPU_LIMIT ?? '2',
      memoryLimit: options.kubernetes?.memoryLimit ?? env.OPENCHAMBER_WORKSPACE_KUBE_MEMORY_LIMIT ?? '4Gi',
      networkPolicy: validateKubernetesNetworkPolicy(options.kubernetes?.networkPolicy ?? env.OPENCHAMBER_WORKSPACE_KUBE_NETWORK_POLICY ?? 'default-deny'),
    },
    appleContainer: {
      cli: optionalString(options.appleContainer?.cli ?? env.OPENCHAMBER_WORKSPACE_APPLE_CONTAINER_CLI) ?? 'container',
      networkMode: optionalString(options.appleContainer?.networkMode ?? env.OPENCHAMBER_WORKSPACE_APPLE_CONTAINER_NETWORK) ?? SECURE_APPLE_CONTAINER_NETWORK,
      memoryLimit: options.appleContainer?.memoryLimit ?? env.OPENCHAMBER_WORKSPACE_APPLE_CONTAINER_MEMORY,
      cpuLimit: options.appleContainer?.cpuLimit ?? env.OPENCHAMBER_WORKSPACE_APPLE_CONTAINER_CPUS,
    },
    egress: {
      httpProxy: optionalString(options.egress?.httpProxy ?? env.OPENCHAMBER_WORKSPACE_EGRESS_HTTP_PROXY),
      noProxy: optionalString(options.egress?.noProxy ?? env.OPENCHAMBER_WORKSPACE_EGRESS_NO_PROXY),
      proxyCIDR: optionalString(options.egress?.proxyCIDR ?? env.OPENCHAMBER_WORKSPACE_EGRESS_PROXY_CIDR),
      dnsCIDRs: splitList(options.egress?.dnsCIDRs ?? env.OPENCHAMBER_WORKSPACE_EGRESS_DNS_CIDRS),
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

export function requireDockerEgress(policy) {
  if (policy.docker.networkMode !== SECURE_DOCKER_NETWORK) return;
  if (policy.egress.httpProxy) {
    validateProxyUrl(policy.egress.httpProxy);
    return;
  }
  throw new PolicyError('Docker secure workspaces require OPENCHAMBER_WORKSPACE_EGRESS_HTTP_PROXY or egress.httpProxy so model-provider traffic has an explicit audited egress path');
}

export function requireKubernetesEgress(policy) {
  if (policy.kubernetes.networkPolicy !== 'default-deny') return;
  if (policy.egress.httpProxy && policy.egress.proxyCIDR && policy.egress.dnsCIDRs.length > 0) {
    validateProxyUrl(policy.egress.httpProxy);
    validateCIDR(policy.egress.proxyCIDR, 'Workspace egress proxy CIDR');
    for (const cidr of policy.egress.dnsCIDRs) validateCIDR(cidr, 'Workspace egress DNS CIDR');
    return;
  }
  throw new PolicyError('Kubernetes secure workspaces require egress.httpProxy, egress.proxyCIDR, and egress.dnsCIDRs so NetworkPolicy can allow only DNS plus proxy traffic');
}

export function requireAppleContainerEgress(policy) {
  if (policy.appleContainer.networkMode !== SECURE_APPLE_CONTAINER_NETWORK) return;
  if (policy.egress.httpProxy) {
    validateProxyUrl(policy.egress.httpProxy);
    return;
  }
  throw new PolicyError('Apple Container secure workspaces require OPENCHAMBER_WORKSPACE_EGRESS_HTTP_PROXY or egress.httpProxy so model-provider traffic has an explicit audited egress path');
}

function validateProxyUrl(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new PolicyError(`Workspace egress proxy URL is invalid: ${value}`);
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new PolicyError(`Workspace egress proxy URL must use http or https: ${value}`);
  }
  if (parsed.username || parsed.password) {
    throw new PolicyError('Workspace egress proxy URL must not include credentials');
  }
}

function validateCIDR(value, label) {
  const [address, prefix, extra] = String(value).split('/');
  const family = isIP(address);
  const prefixNumber = Number(prefix);
  const maxPrefix = family === 4 ? 32 : family === 6 ? 128 : 0;
  if (extra !== undefined || !family || prefix === undefined || !Number.isInteger(prefixNumber) || prefixNumber < 0 || prefixNumber > maxPrefix) {
    throw new PolicyError(`${label} must be a valid IPv4 or IPv6 CIDR`);
  }
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

function optionalString(value) {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed || undefined;
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

function normalizeDockerNetworkMode(mode) {
  const normalized = String(mode || 'bridge');
  return normalized === 'default' ? 'bridge' : normalized;
}

function validateDockerNetworkMode(mode, allowedNetworks) {
  if (mode === 'none') return;
  if (mode === SECURE_DOCKER_NETWORK) return;
  if (allowedNetworks.includes(mode)) return;
  throw new PolicyError(`Docker network mode is not allowed for secure workspaces: ${mode}`);
}

function validateKubernetesNetworkPolicy(value) {
  const normalized = String(value || 'default');
  if (normalized === 'default' || normalized === 'default-deny') return 'default-deny';
  if (normalized === 'disabled') return normalized;
  if (normalized === 'restricted') {
    throw new PolicyError('Kubernetes restricted NetworkPolicy requires explicit allowed selectors and is not enabled by this plugin yet');
  }
  throw new PolicyError(`Kubernetes network policy mode is not supported: ${normalized}`);
}

function validateAllowedValue(label, value, allowedValues) {
  if (!value || allowedValues.length === 0) return;
  if (allowedValues.includes(String(value))) return;
  throw new PolicyError(`${label} is not allowed by secure workspace policy: ${value}`);
}
