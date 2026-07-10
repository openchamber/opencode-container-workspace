import { createDockerProvider } from './providers/docker.js';
import { createKubernetesProvider } from './providers/kubernetes.js';
import { readPolicy } from './policy.js';

export default async function openchamberWorkspacePlugin(input, options = {}) {
  const policy = readPolicy(options.policy ?? options);
  const sourceDirectory = input.directory;
  const providers = [
    createDockerProvider({ policy, sourceDirectory }),
    createKubernetesProvider({ policy, sourceDirectory }),
  ].sort((left, right) => {
    if (left.kind === policy.defaultProvider) return -1;
    if (right.kind === policy.defaultProvider) return 1;
    return 0;
  });

  for (const provider of providers) {
    input.experimental_workspace.register(provider.kind, {
      name: provider.kind === 'docker' ? 'Docker' : 'Kubernetes',
      description: provider.kind === 'docker'
        ? 'Create an isolated Docker workspace managed by OpenChamber'
        : 'Create an isolated Kubernetes workspace managed by OpenChamber',
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

  return {};
}
