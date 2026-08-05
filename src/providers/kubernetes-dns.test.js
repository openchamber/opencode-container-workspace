import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createKubernetesProvider, resetKubernetesDiscoveryCache } from './kubernetes.js';

const BASE_POLICY = {
  defaultProvider: 'kubernetes',
  defaultImage: 'ghcr.io/openchamber/opencode-workspace@sha256:1111111111111111111111111111111111111111111111111111111111111111',
  allowedImages: [],
  requirePinnedImage: true,
  modelAuth: 'explicit-opencode-auth-content',
  egress: {
    mode: 'managed',
    gatewayImage: 'ghcr.io/openchamber/workspace-egress-gateway@sha256:2222222222222222222222222222222222222222222222222222222222222222',
    allowedDomains: ['api.anthropic.com'],
    allowedCIDRs: [],
    allowedPorts: [443],
    dnsCIDRs: [],
    gatewayPolicy: { allowedDomains: ['api.anthropic.com'], allowedCIDRs: [], allowedPorts: [443] },
  },
  kubernetes: {
    context: 'provided-cluster', namespace: 'workspaces', connectivity: 'port-forward',
    storage: '8Gi', cpuRequest: '250m', memoryRequest: '512Mi', cpuLimit: '2', memoryLimit: '4Gi',
    ingress: { ingressClassName: '', hostTemplate: '', pathTemplate: '/', tls: { mode: 'existing-secret', secretName: '' }, controllerNamespaceSelector: {}, controllerPodSelector: {}, annotations: {} },
  },
};

/** Answers the preflight sequence so a test only states the DNS services the cluster has. */
function clusterWith({ dnsServices, dnsError, policy = BASE_POLICY }) {
  const calls = [];
  const run = vi.fn(async (command, args) => {
    calls.push(args.join(' '));
    const joined = args.join(' ');
    if (joined.includes('version --client')) return { stdout: 'Client Version: v1.36.1' };
    if (joined.includes('get namespace')) return { stdout: 'namespace/workspaces' };
    if (joined.includes('auth can-i')) return { stdout: 'yes' };
    if (joined.includes('k8s-app=kube-dns')) {
      if (dnsError) throw Object.assign(new Error('forbidden'), { stderr: 'services is forbidden' });
      return { stdout: JSON.stringify({ items: dnsServices }) };
    }
    throw new Error(`unexpected kubectl call: ${joined}`);
  });
  return { run, calls, policy };
}

vi.mock('../process.js', async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, run: (...args) => globalThis.__kubectlRun(...args) };
});

const validate = async (fixture) => {
  globalThis.__kubectlRun = fixture.run;
  return createKubernetesProvider({ policy: fixture.policy, sourceDirectory: process.cwd() }).validate();
};

describe('kubernetes cluster DNS discovery', () => {
  beforeEach(() => resetKubernetesDiscoveryCache());

  it('discovers the cluster DNS address instead of demanding it be configured', async () => {
    const fixture = clusterWith({ dnsServices: [{ spec: { clusterIP: '10.96.0.10' } }] });

    await expect(validate(fixture)).resolves.toMatchObject({ available: true });
    expect(fixture.calls.some((call) => call.includes('k8s-app=kube-dns'))).toBe(true);
  });

  it('covers both addresses of a dual-stack DNS service', async () => {
    const fixture = clusterWith({ dnsServices: [{ spec: { clusterIPs: ['10.96.0.10', 'fd00::10'] } }] });

    await expect(validate(fixture)).resolves.toMatchObject({ available: true });
  });

  it('keeps a configured range authoritative and does not query the cluster for it', async () => {
    const policy = { ...BASE_POLICY, egress: { ...BASE_POLICY.egress, dnsCIDRs: ['10.43.0.10/32'] } };
    const fixture = clusterWith({ dnsServices: [{ spec: { clusterIP: '10.96.0.10' } }], policy });

    await expect(validate(fixture)).resolves.toMatchObject({ available: true });
    expect(fixture.calls.some((call) => call.includes('k8s-app=kube-dns'))).toBe(false);
  });

  it('asks for the address only when the cluster will not reveal it', async () => {
    const fixture = clusterWith({ dnsServices: [], dnsError: true });

    await expect(validate(fixture)).rejects.toMatchObject({ code: 'WORKSPACE_PROVIDER_DNS_UNRESOLVED' });
  });

  it('treats a headless DNS service as no answer rather than a usable range', async () => {
    const fixture = clusterWith({ dnsServices: [{ spec: { clusterIP: 'None' } }] });

    await expect(validate(fixture)).rejects.toMatchObject({ code: 'WORKSPACE_PROVIDER_DNS_UNRESOLVED' });
  });

  it('reports an unreachable cluster before complaining about the egress policy', async () => {
    const fixture = clusterWith({ dnsServices: [] });
    fixture.run.mockImplementation(async (command, args) => {
      const joined = args.join(' ');
      if (joined.includes('version --client')) return { stdout: 'Client Version: v1.36.1' };
      if (joined.includes('get namespace')) throw Object.assign(new Error('connection refused'), { stderr: 'Unable to connect to the server' });
      throw new Error(`unexpected kubectl call: ${joined}`);
    });

    await expect(validate(fixture)).rejects.toMatchObject({ code: 'WORKSPACE_PROVIDER_CLUSTER_UNREACHABLE' });
  });
});
