import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import { readPolicy } from '../policy.js';
import { createKubernetesProvider } from './kubernetes.js';

const image = process.env.OPENCHAMBER_KUBERNETES_WORKSPACE_INTEGRATION_IMAGE;
const gatewayImage = process.env.OPENCHAMBER_KUBERNETES_WORKSPACE_INTEGRATION_GATEWAY_IMAGE;
const context = process.env.OPENCHAMBER_KUBERNETES_WORKSPACE_INTEGRATION_CONTEXT;
const namespace = process.env.OPENCHAMBER_KUBERNETES_WORKSPACE_INTEGRATION_NAMESPACE;
const dnsCIDR = process.env.OPENCHAMBER_KUBERNETES_WORKSPACE_INTEGRATION_DNS_CIDR;
const integrationIt = image && gatewayImage && context && namespace && dnsCIDR ? it : it.skip;

describe('kubernetes workspace provider integration', () => {
  integrationIt('creates, exports, reconciles, and removes an isolated workspace', async () => {
    const sourceDirectory = await mkdtemp(join(process.cwd(), '.openchamber-kubernetes-workspace-source-'));
    const stateDirectory = await mkdtemp(join(process.cwd(), '.openchamber-kubernetes-workspace-state-'));
    process.env.OPENCHAMBER_WORKSPACE_STATE_DIR = stateDirectory;
    const policy = readPolicy({
      defaultImage: image,
      allowedImages: [image],
      egress: { mode: 'managed', gatewayImage, preset: 'restricted', dnsCIDRs: [dnsCIDR] },
      kubernetes: {
        context,
        namespace,
        allowedContexts: [context],
        allowedNamespaces: [namespace],
        storage: '64Mi',
        cpuRequest: '25m',
        memoryRequest: '128Mi',
        cpuLimit: '300m',
        memoryLimit: '384Mi',
      },
    });
    const provider = createKubernetesProvider({ policy, sourceDirectory });
    const info = provider.configure({ id: `integration:${Date.now()}`, projectID: 'integration' });
    let created = false;
    let cleanupCompleted = false;

    try {
      await writeFile(join(sourceDirectory, 'README.md'), 'kubernetes integration workspace\n');
      await provider.create(info);
      created = true;
      const target = await provider.target(info);
      expect((await fetch(new URL('/global/health', target.url), { headers: target.headers })).ok).toBe(true);

      const mutation = spawnSync('kubectl', [
        '--context', context, 'exec', `deployment/${info.extra.resourceRefs.deployment}`, '-n', namespace, '--',
        'sh', '-lc', "printf 'changed\\n' > README.md; printf 'added\\n' > added.txt",
      ], { encoding: 'utf8', windowsHide: true });
      expect(mutation.status, mutation.stderr || mutation.stdout).toBe(0);
      const artifact = await provider.exportWorkspace(info);
      expect(artifact.files.map((entry) => entry.kind)).toEqual(expect.arrayContaining(['modify', 'add']));
      await expect(provider.reconcile(info)).resolves.toMatchObject({ status: 'ready' });
    } finally {
      try {
        if (created || process.env.OPENCHAMBER_KUBERNETES_WORKSPACE_INTEGRATION_PRESERVE_ON_FAILURE !== 'true') {
          await provider.remove(info);
          cleanupCompleted = true;
        }
      } finally {
        delete process.env.OPENCHAMBER_WORKSPACE_STATE_DIR;
        await rm(sourceDirectory, { recursive: true, force: true });
        if (cleanupCompleted) await rm(stateDirectory, { recursive: true, force: true });
      }
    }
  }, 600_000);
});
