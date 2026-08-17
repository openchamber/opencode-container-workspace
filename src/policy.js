import { PolicyError } from './errors.js';
import { isIP } from 'node:net';
import { readFileSync } from 'node:fs';
import { parseEgressPolicy } from './egress-gateway.js';

const DEFAULT_IMAGE = '';
export const SECURE_DOCKER_NETWORK = 'per-workspace-internal';
export const SECURE_APPLE_CONTAINER_NETWORK = 'per-workspace-host-only';

export function readPolicy(options = {}) {
  const env = process.env;
  const allowedImages = splitList(options.allowedImages ?? env.OPENCHAMBER_WORKSPACE_ALLOWED_IMAGES);
  if (allowedImages.some((image) => image.includes('*'))) throw new PolicyError('Workspace image allow-list entries must be exact digest references');
  const defaultImage = String(options.defaultImage ?? env.OPENCHAMBER_WORKSPACE_IMAGE ?? DEFAULT_IMAGE);
  const rawDefaultProvider = options.defaultProvider ?? env.OPENCHAMBER_WORKSPACE_DEFAULT_PROVIDER;
  const defaultProvider = validateDefaultProvider(rawDefaultProvider ?? 'docker');
  const requirePinnedImage = bool(options.requirePinnedImage ?? env.OPENCHAMBER_WORKSPACE_REQUIRE_PINNED_IMAGE, true);
  if (!requirePinnedImage) throw new PolicyError('Workspace image digest enforcement cannot be disabled');
  const dockerNetworkMode = normalizeDockerNetworkMode(options.docker?.networkMode ?? env.OPENCHAMBER_WORKSPACE_DOCKER_NETWORK ?? 'per-workspace-internal');
  validateDockerNetworkMode(dockerNetworkMode);
  const kubernetesNamespace = String(options.kubernetes?.namespace ?? env.OPENCHAMBER_WORKSPACE_KUBE_NAMESPACE ?? 'openchamber-workspaces');
  const kubernetesContext = options.kubernetes?.context ?? env.OPENCHAMBER_WORKSPACE_KUBE_CONTEXT;
  validateAllowedValue('Kubernetes context', kubernetesContext, splitList(options.kubernetes?.allowedContexts ?? env.OPENCHAMBER_WORKSPACE_KUBE_ALLOWED_CONTEXTS));
  validateAllowedValue('Kubernetes namespace', kubernetesNamespace, splitList(options.kubernetes?.allowedNamespaces ?? env.OPENCHAMBER_WORKSPACE_KUBE_ALLOWED_NAMESPACES));
  const egress = readEgressPolicy(options.egress ?? {}, env);
  const kubernetesConnectivity = validateKubernetesConnectivity(options.kubernetes?.connectivity ?? env.OPENCHAMBER_WORKSPACE_KUBE_CONNECTIVITY ?? 'port-forward');
  const kubernetesIngress = kubernetesConnectivity === 'ingress' ? parseKubernetesIngressPolicy(options.kubernetes?.ingress) : undefined;

  return {
    version: 1,
    allowedImages,
    defaultProvider,
    requirePinnedImage: true,
    defaultImage,
    docker: {
      networkMode: dockerNetworkMode,
      memoryLimit: options.docker?.memoryLimit ?? env.OPENCHAMBER_WORKSPACE_DOCKER_MEMORY,
      cpuLimit: options.docker?.cpuLimit ?? env.OPENCHAMBER_WORKSPACE_DOCKER_CPUS,
      pidsLimit: positiveInteger(options.docker?.pidsLimit ?? env.OPENCHAMBER_WORKSPACE_DOCKER_PIDS, 512),
    },
    kubernetes: {
      context: kubernetesContext,
      namespace: kubernetesNamespace,
      allowedContexts: splitList(options.kubernetes?.allowedContexts ?? env.OPENCHAMBER_WORKSPACE_KUBE_ALLOWED_CONTEXTS),
      allowedNamespaces: splitList(options.kubernetes?.allowedNamespaces ?? env.OPENCHAMBER_WORKSPACE_KUBE_ALLOWED_NAMESPACES),
      connectivity: kubernetesConnectivity,
      ingress: kubernetesIngress,
      storage: options.kubernetes?.storage ?? env.OPENCHAMBER_WORKSPACE_KUBE_STORAGE ?? '8Gi',
      cpuRequest: options.kubernetes?.cpuRequest ?? env.OPENCHAMBER_WORKSPACE_KUBE_CPU_REQUEST ?? '250m',
      memoryRequest: options.kubernetes?.memoryRequest ?? env.OPENCHAMBER_WORKSPACE_KUBE_MEMORY_REQUEST ?? '512Mi',
      cpuLimit: options.kubernetes?.cpuLimit ?? env.OPENCHAMBER_WORKSPACE_KUBE_CPU_LIMIT ?? '2',
      memoryLimit: options.kubernetes?.memoryLimit ?? env.OPENCHAMBER_WORKSPACE_KUBE_MEMORY_LIMIT ?? '4Gi',
      networkPolicy: validateKubernetesNetworkPolicy(options.kubernetes?.networkPolicy ?? env.OPENCHAMBER_WORKSPACE_KUBE_NETWORK_POLICY ?? 'default-deny'),
    },
    appleContainer: {
      cli: optionalString(options.appleContainer?.cli ?? env.OPENCHAMBER_WORKSPACE_APPLE_CONTAINER_CLI) ?? 'container',
      networkMode: validateAppleNetworkMode(optionalString(options.appleContainer?.networkMode ?? env.OPENCHAMBER_WORKSPACE_APPLE_CONTAINER_NETWORK) ?? 'per-workspace-host-only'),
      memoryLimit: options.appleContainer?.memoryLimit ?? env.OPENCHAMBER_WORKSPACE_APPLE_CONTAINER_MEMORY,
      cpuLimit: options.appleContainer?.cpuLimit ?? env.OPENCHAMBER_WORKSPACE_APPLE_CONTAINER_CPUS,
    },
    egress,
    retention: {
      preserveOnDelete: bool(options.retention?.preserveOnDelete ?? env.OPENCHAMBER_WORKSPACE_PRESERVE_ON_DELETE, false),
    },
    secrets: {
      mode: validateSecretMode(options.secrets?.mode ?? env.OPENCHAMBER_WORKSPACE_SECRET_MODE ?? 'file'),
    },
    credentials: {
      modelAuth: validateModelAuthGrant(options.credentials?.modelAuth ?? env.OPENCHAMBER_WORKSPACE_MODEL_AUTH ?? 'none'),
    },
  };
}

export function requireDockerEgress(policy) {
  if (policy.egress.mode === 'managed') {
    validateGatewayImage(policy.egress.gatewayImage);
    return;
  }
  if (policy.egress.proxyUrl) {
    validateProxyUrl(policy.egress.proxyUrl);
    return;
  }
  throw new PolicyError('Docker external egress requires egress.proxyUrl');
}

export function requireKubernetesEgress(policy) {
  for (const cidr of policy.egress.dnsCIDRs) validateCIDR(cidr, 'Workspace egress DNS CIDR');
  if (policy.egress.mode === 'managed') {
    validateGatewayImage(policy.egress.gatewayImage);
    return;
  }
  if (policy.egress.proxyUrl && policy.egress.proxyCIDR) {
    validateProxyUrl(policy.egress.proxyUrl);
    validateCIDR(policy.egress.proxyCIDR, 'Workspace egress proxy CIDR');
    return;
  }
  throw new PolicyError('Kubernetes external egress requires egress.proxyUrl and egress.proxyCIDR');
}

export function requireAppleContainerEgress(policy) {
  if (policy.egress.mode === 'managed') {
    validateGatewayImage(policy.egress.gatewayImage);
    return;
  }
  if (policy.egress.proxyUrl) {
    validateProxyUrl(policy.egress.proxyUrl);
    return;
  }
  throw new PolicyError('Apple Container external egress requires egress.proxyUrl');
}

function readEgressPolicy(options, env) {
  const configuredProxy = optionalString(options.proxyUrl ?? env.OPENCHAMBER_WORKSPACE_EGRESS_HTTP_PROXY);
  const mode = options.mode ?? (configuredProxy ? 'external' : 'managed');
  const dnsCIDRs = splitList(options.dnsCIDRs ?? env.OPENCHAMBER_WORKSPACE_EGRESS_DNS_CIDRS);
  const noProxy = optionalString(options.noProxy ?? env.OPENCHAMBER_WORKSPACE_EGRESS_NO_PROXY);
  if (mode === 'external') {
    if (options.proxyCredentialRef) throw new PolicyError('External proxy credential references require a configured host secret resolver');
    const proxyUrl = configuredProxy;
    if (proxyUrl) validateProxyUrl(proxyUrl);
    return {
      mode,
      proxyUrl,
      proxyCIDR: optionalString(options.proxyCIDR ?? env.OPENCHAMBER_WORKSPACE_EGRESS_PROXY_CIDR),
      dnsCIDRs,
      noProxy,
    };
  }
  if (mode !== 'managed') throw new PolicyError(`Unsupported egress mode: ${String(mode)}`);
  const preset = options.preset ?? 'restricted';
  if (preset !== 'restricted' && preset !== 'custom') throw new PolicyError(`Unsupported managed egress preset: ${String(preset)}`);
  const domainSets = splitList(options.allowedDomainSets);
  if (domainSets.some((set) => set !== 'restricted')) throw new PolicyError('Unknown managed egress domain set');
  const presetDomains = preset === 'restricted' || domainSets.includes('restricted') ? RESTRICTED_DOMAINS : [];
  const gatewayPolicy = {
    version: 1,
    allowedDomains: [...presetDomains, ...splitList(options.allowedDomains)],
    allowedCIDRs: splitList(options.allowedCIDRs),
    allowedPorts: Array.isArray(options.allowedPorts) ? options.allowedPorts : [80, 443],
  };
  parseEgressPolicy(gatewayPolicy);
  return {
    mode,
    gatewayImage: optionalString(options.gatewayImage ?? env.OPENCHAMBER_WORKSPACE_EGRESS_GATEWAY_IMAGE),
    preset,
    gatewayPolicy,
    dnsCIDRs,
    noProxy,
  };
}

const EGRESS_PRESETS = JSON.parse(readFileSync(new URL('../egress-image/egress-presets.json', import.meta.url), 'utf8'));
if (EGRESS_PRESETS?.version !== 1 || !Array.isArray(EGRESS_PRESETS?.sets?.restricted)) throw new PolicyError('Workspace egress preset file is invalid');
const RESTRICTED_DOMAINS = Object.freeze(EGRESS_PRESETS.sets.restricted.map(String));

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
    throw new PolicyError(`Workspace image must be pinned by sha256 digest: ${normalized}`);
  }
  if (policy.allowedImages.length > 0 && !policy.allowedImages.some((allowed) => imageMatches(allowed, normalized))) {
    throw new PolicyError(`Workspace image is not allowed by policy: ${normalized}`);
  }
  return normalized;
}

function validateGatewayImage(image) {
  const normalized = String(image ?? '').trim();
  if (!isPinnedImage(normalized)) throw new PolicyError('Managed egress requires a sha256 digest-pinned gateway image');
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

function optionalString(value) {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed || undefined;
}

function isPinnedImage(image) {
  return /@sha256:[a-f0-9]{64}$/i.test(image);
}

function imageMatches(pattern, image) {
  return pattern === image;
}

function normalizeDockerNetworkMode(mode) {
  const normalized = String(mode || 'bridge');
  return normalized === 'default' ? 'bridge' : normalized;
}

function validateDockerNetworkMode(mode) {
  if (mode === 'per-workspace-internal') return;
  throw new PolicyError(`Docker network mode is not allowed for secure workspaces: ${mode}`);
}

function validateDefaultProvider(value) {
  if (value === 'docker' || value === 'kubernetes' || value === 'apple-container') return value;
  throw new PolicyError(`Unsupported default workspace provider: ${String(value)}`);
}

function validateKubernetesNetworkPolicy(value) {
  const normalized = String(value || 'default');
  if (normalized === 'default' || normalized === 'default-deny') return 'default-deny';
  if (normalized === 'disabled') throw new PolicyError('Kubernetes NetworkPolicy cannot be disabled for secure workspaces');
  if (normalized === 'restricted') {
    throw new PolicyError('Kubernetes restricted NetworkPolicy requires explicit allowed selectors and is not enabled by this plugin yet');
  }
  throw new PolicyError(`Kubernetes network policy mode is not supported: ${normalized}`);
}

function validateKubernetesConnectivity(value) {
  if (value === 'port-forward' || value === 'ingress') return value;
  throw new PolicyError(`Kubernetes connectivity mode is not supported: ${String(value)}`);
}

function parseKubernetesIngressPolicy(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new PolicyError('Kubernetes ingress requires a complete ingress policy');
  const ingressClassName = requiredString(value.ingressClassName, 'Kubernetes ingressClassName');
  const hostTemplate = requiredString(value.hostTemplate, 'Kubernetes ingress hostTemplate');
  const pathTemplate = requiredString(value.pathTemplate, 'Kubernetes ingress pathTemplate');
  if (!hostTemplate.includes('{resourceID}')) throw new PolicyError('Kubernetes ingress hostTemplate must contain {resourceID}');
  if (pathTemplate !== '/') throw new PolicyError('Kubernetes ingress pathTemplate must be / unless a reviewed controller rewrite contract is implemented');
  const testHost = hostTemplate.replaceAll('{resourceID}', 'ws-0123456789abcdef');
  if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(testHost)) throw new PolicyError('Kubernetes ingress hostTemplate does not produce a valid DNS host');
  const tls = value.tls;
  if (!tls || typeof tls !== 'object') throw new PolicyError('Kubernetes ingress TLS policy is required');
  if (tls.mode !== 'existing-secret' && tls.mode !== 'cert-manager') throw new PolicyError('Kubernetes ingress TLS mode must be existing-secret or cert-manager');
  const normalizedTLS = tls.mode === 'existing-secret'
    ? { mode: tls.mode, secretName: requiredKubernetesName(tls.secretName, 'Kubernetes ingress TLS secret') }
    : { mode: tls.mode, clusterIssuer: requiredKubernetesName(tls.clusterIssuer, 'Kubernetes cert-manager clusterIssuer') };
  const controllerNamespaceSelector = parseSelector(value.controllerNamespaceSelector, 'controller namespace');
  const controllerPodSelector = parseSelector(value.controllerPodSelector, 'controller pod');
  const annotations = value.annotations ?? {};
  if (!annotations || typeof annotations !== 'object' || Array.isArray(annotations)) throw new PolicyError('Kubernetes ingress annotations must be an object');
  const allowedAnnotationPrefixes = ['nginx.ingress.kubernetes.io/proxy-body-size', 'nginx.ingress.kubernetes.io/proxy-read-timeout', 'nginx.ingress.kubernetes.io/proxy-send-timeout'];
  for (const [key, annotationValue] of Object.entries(annotations)) {
    if (!allowedAnnotationPrefixes.includes(key) || typeof annotationValue !== 'string') throw new PolicyError(`Kubernetes ingress annotation is not allowed: ${key}`);
  }
  return { ingressClassName, hostTemplate, pathTemplate, tls: normalizedTLS, controllerNamespaceSelector, controllerPodSelector, annotations: { ...annotations } };
}

function parseSelector(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length === 0) throw new PolicyError(`Kubernetes ingress ${label} selector is required`);
  const result = {};
  for (const [key, selectorValue] of Object.entries(value)) {
    if (!/^[A-Za-z0-9]([A-Za-z0-9_.\/-]{0,251}[A-Za-z0-9])?$/.test(key) || !/^[A-Za-z0-9]([A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?$/.test(String(selectorValue))) throw new PolicyError(`Kubernetes ingress ${label} selector is invalid`);
    result[key] = String(selectorValue);
  }
  return result;
}

function requiredString(value, label) {
  const normalized = optionalString(value);
  if (!normalized) throw new PolicyError(`${label} is required`);
  return normalized;
}

function requiredKubernetesName(value, label) {
  const normalized = requiredString(value, label);
  if (!/^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$/.test(normalized)) throw new PolicyError(`${label} is invalid`);
  return normalized;
}

function validateSecretMode(value) {
  if (value === 'file') return value;
  throw new PolicyError('Workspace secrets must use provider-backed files');
}

function validateAppleNetworkMode(value) {
  if (value === 'per-workspace-host-only') return value;
  throw new PolicyError(`Apple Container network mode is not allowed for secure workspaces: ${value}`);
}

function validateModelAuthGrant(value) {
  if (value === 'none' || value === 'explicit-opencode-auth-content') return value;
  throw new PolicyError('Workspace model authentication must be none or explicit-opencode-auth-content');
}

function positiveInteger(value, fallback) {
  const parsed = typeof value === 'string' ? Number(value) : value;
  if (parsed === undefined) return fallback;
  if (!Number.isInteger(parsed) || parsed <= 0) throw new PolicyError('Workspace process limit must be a positive integer');
  return parsed;
}

function validateAllowedValue(label, value, allowedValues) {
  if (!value || allowedValues.length === 0) return;
  if (allowedValues.includes(String(value))) return;
  throw new PolicyError(`${label} is not allowed by secure workspace policy: ${value}`);
}
