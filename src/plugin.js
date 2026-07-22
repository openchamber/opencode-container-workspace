import { createDockerProvider } from './providers/docker.js';
import { createKubernetesProvider } from './providers/kubernetes.js';
import { createAppleContainerProvider } from './providers/apple-container.js';
import { readPolicy } from './policy.js';
import { readMetadata } from './metadata.js';
import { closeTransportShim, ensureTransportShim } from './transport-shim.js';

export default async function openchamberWorkspacePlugin(input, options = {}) {
  const registry = input?.experimental_workspace;
  if (!registry || typeof registry.register !== 'function') {
    return {
      openchamber: {
        secureWorkspaces: {
          registered: false,
          reason: 'OpenCode experimental workspace API is not available',
        },
      },
    };
  }

  const policy = readPolicy(options.policy ?? options);
  const sourceDirectory = input.directory;
  const providers = [
    createDockerProvider({ policy, sourceDirectory }),
    createKubernetesProvider({ policy, sourceDirectory }),
    createAppleContainerProvider({ policy, sourceDirectory }),
  ].sort((left, right) => {
    if (left.kind === policy.defaultProvider) return -1;
    if (right.kind === policy.defaultProvider) return 1;
    return 0;
  });

  for (const provider of providers) {
    const label = providerLabel(provider.kind);
    registerCompatibilityAdapter(registry, provider.kind, {
      name: label,
      description: `Create an isolated ${label} workspace managed by OpenChamber`,
      configure(info, context) {
        return provider.configure(info, context);
      },
      async create(info, env, from, context) {
        await provider.create(info, env, from, context);
      },
      async remove(info, context) {
        const providerResourceID = readMetadata(info, provider.kind, policy).providerResourceID;
        try {
          await provider.remove(info, context);
        } finally {
          await closeTransportShim(providerResourceID);
        }
      },
      async target(info, context) {
        const metadata = readMetadata(info, provider.kind, policy);
        return ensureTransportShim({
          identity: metadata,
          getTarget: () => provider.target(info, context),
          targetPolicy: transportTargetPolicy(provider.kind, policy, metadata.providerResourceID),
        });
      },
      async list(context) {
        return provider.list(context);
      },
    });
  }

  return { openchamber: { secureWorkspaces: { registered: true } } };
}

function transportTargetPolicy(provider, policy, providerResourceID) {
  if (provider !== 'kubernetes' || policy.kubernetes.connectivity === 'port-forward') return { mode: 'loopback' };
  const host = policy.kubernetes.ingress.hostTemplate.replaceAll('{resourceID}', providerResourceID);
  return { mode: 'https', origin: `https://${host}` };
}

function registerCompatibilityAdapter(registry, kind, adapter) {
  // OpenCode supports list internally, but the pinned public plugin contract does not yet declare it.
  registry.register(kind, adapter);
}

function providerLabel(kind) {
  if (kind === 'docker') return 'Docker';
  if (kind === 'kubernetes') return 'Kubernetes';
  if (kind === 'apple-container') return 'Apple Container';
  return kind;
}
