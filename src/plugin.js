import { createDockerProvider } from './providers/docker.js';
import { createKubernetesProvider } from './providers/kubernetes.js';
import { createAppleContainerProvider } from './providers/apple-container.js';
import { readPolicy } from './policy.js';

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
    registry.register(provider.kind, {
      name: label,
      description: `Create an isolated ${label} workspace managed by OpenChamber`,
      configure(info, context) {
        return provider.configure(info, context);
      },
      async create(info, env, from, context) {
        await provider.create(info, env, from, context);
      },
      async remove(info, context) {
        await provider.remove(info, context);
      },
      async target(info, context) {
        return provider.target(info, context);
      },
      async list(context) {
        return provider.list(context);
      },
      async exportDiff(info, context) {
        return provider.exportDiff(info, context);
      },
    });
  }

  return { openchamber: { secureWorkspaces: { registered: true } } };
}

function providerLabel(kind) {
  if (kind === 'docker') return 'Docker';
  if (kind === 'kubernetes') return 'Kubernetes';
  if (kind === 'apple-container') return 'Apple Container';
  return kind;
}
