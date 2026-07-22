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
const connectivity = process.env.OPENCHAMBER_KUBERNETES_WORKSPACE_INTEGRATION_CONNECTIVITY ?? 'port-forward';
const ingressClassName = process.env.OPENCHAMBER_KUBERNETES_WORKSPACE_INTEGRATION_INGRESS_CLASS;
const ingressHostTemplate = process.env.OPENCHAMBER_KUBERNETES_WORKSPACE_INTEGRATION_INGRESS_HOST_TEMPLATE;
const ingressTLSMode = process.env.OPENCHAMBER_KUBERNETES_WORKSPACE_INTEGRATION_INGRESS_TLS_MODE ?? 'existing-secret';
const ingressTLSSecret = process.env.OPENCHAMBER_KUBERNETES_WORKSPACE_INTEGRATION_INGRESS_TLS_SECRET;
const ingressTLSIssuer = process.env.OPENCHAMBER_KUBERNETES_WORKSPACE_INTEGRATION_INGRESS_TLS_ISSUER;
const ingressControllerNamespace = process.env.OPENCHAMBER_KUBERNETES_WORKSPACE_INTEGRATION_INGRESS_CONTROLLER_NAMESPACE;
const ingressControllerPodLabel = process.env.OPENCHAMBER_KUBERNETES_WORKSPACE_INTEGRATION_INGRESS_CONTROLLER_POD_LABEL;
const ingressTLSConfigured = ingressTLSMode === 'existing-secret' ? ingressTLSSecret : ingressTLSMode === 'cert-manager' && ingressTLSIssuer;
const ingressConfigured = connectivity === 'port-forward' || (connectivity === 'ingress' && ingressClassName && ingressHostTemplate && ingressTLSConfigured && ingressControllerNamespace && ingressControllerPodLabel);
const integrationIt = image && gatewayImage && context && namespace && dnsCIDR && ingressConfigured ? it : it.skip;

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
        connectivity,
        ...(connectivity === 'ingress' ? {
          ingress: {
            ingressClassName,
            hostTemplate: ingressHostTemplate,
            pathTemplate: '/',
            tls: ingressTLSMode === 'existing-secret'
              ? { mode: ingressTLSMode, secretName: ingressTLSSecret }
              : { mode: ingressTLSMode, clusterIssuer: ingressTLSIssuer },
            controllerNamespaceSelector: { 'kubernetes.io/metadata.name': ingressControllerNamespace },
            controllerPodSelector: parseSelector(ingressControllerPodLabel),
          },
        } : {}),
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
      expect((await fetch(new URL('/global/health', target.url))).status).toBe(401);

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
          if (info.extra.resourceRefs.ingressTLSSecret) {
            const secret = spawnSync('kubectl', ['--context', context, 'get', 'secret', info.extra.resourceRefs.ingressTLSSecret, '-n', namespace], { encoding: 'utf8', windowsHide: true });
            expect(secret.status).not.toBe(0);
          }
        }
      } finally {
        delete process.env.OPENCHAMBER_WORKSPACE_STATE_DIR;
        await rm(sourceDirectory, { recursive: true, force: true });
        if (cleanupCompleted) await rm(stateDirectory, { recursive: true, force: true });
      }
    }
  }, 600_000);
});

function parseSelector(value) {
  const separator = value.indexOf('=');
  if (separator <= 0 || separator === value.length - 1) throw new Error('Kubernetes integration ingress controller pod label must be key=value');
  return { [value.slice(0, separator)]: value.slice(separator + 1) };
}
