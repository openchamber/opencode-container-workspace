import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { SECURE_DOCKER_NETWORK, readPolicy, requireDockerEgress, requireKubernetesEgress, validateImage } from './policy.js';

describe('workspace policy', () => {
  const savedEnv = { ...process.env };

  beforeEach(() => {
    delete process.env.OPENCHAMBER_WORKSPACE_DOCKER_NETWORK;
    delete process.env.OPENCHAMBER_WORKSPACE_DOCKER_ALLOWED_NETWORKS;
    delete process.env.OPENCHAMBER_WORKSPACE_KUBE_NETWORK_POLICY;
  });

  afterEach(() => {
    process.env = { ...savedEnv };
  });

  it('uses the owned internal Docker network by default', () => {
    expect(readPolicy().docker).toMatchObject({ networkMode: SECURE_DOCKER_NETWORK });
  });

  it('rejects connected Docker networks even when legacy allow-list input is present', () => {
    expect(() => readPolicy({ docker: { networkMode: 'bridge' } })).toThrow(/Docker network mode is not allowed/);
    expect(() => readPolicy({ docker: { networkMode: 'bridge', allowedNetworks: ['bridge'] } })).toThrow(/Docker network mode is not allowed/);
  });

  it('requires image digests when pinning is enabled', () => {
    const policy = readPolicy({ defaultImage: 'workspace:1.0.0' });
    expect(() => validateImage(policy, policy.defaultImage)).toThrow(/sha256 digest/);
  });

  it('rejects policy downgrades and unknown providers', () => {
    expect(() => readPolicy({ requirePinnedImage: false })).toThrow(/cannot be disabled/);
    expect(() => readPolicy({ allowedImages: ['registry.example/workspace@sha256:*'] })).toThrow(/must be exact/);
    expect(() => readPolicy({ defaultProvider: 'unknown' })).toThrow(/Unsupported default/);
  });

  it('rejects Kubernetes restricted NetworkPolicy until explicit selectors are supported', () => {
    expect(() => readPolicy({ kubernetes: { networkPolicy: 'restricted' } })).toThrow(/requires explicit allowed selectors/);
  });

  it('uses default-deny Kubernetes NetworkPolicy by default', () => {
    expect(readPolicy().kubernetes.networkPolicy).toBe('default-deny');
  });

  it('requires explicit Docker egress proxy for the owned internal network', () => {
    expect(() => requireDockerEgress(readPolicy())).toThrow(/egress/i);
    expect(() => requireDockerEgress(readPolicy({ egress: { mode: 'external', proxyUrl: 'http://proxy.openchamber:3128' } }))).not.toThrow();
  });

  it('requires explicit Kubernetes proxy and DNS egress for default-deny policy', () => {
    expect(() => requireKubernetesEgress(readPolicy())).toThrow(/egress/i);
    expect(() => requireKubernetesEgress(readPolicy({
      egress: { mode: 'external', proxyUrl: 'http://10.0.0.10:3128', proxyCIDR: '10.0.0.10/32', dnsCIDRs: ['10.0.0.53/32'] },
    }))).not.toThrow();
  });

  it('validates managed egress gateway image and destination policy', () => {
    const policy = readPolicy({ egress: { mode: 'managed', gatewayImage: 'gateway@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', preset: 'custom', allowedDomains: ['api.example.com'], dnsCIDRs: ['10.0.0.53/32'] } });
    expect(policy.egress.gatewayPolicy).toMatchObject({ version: 1, allowedDomains: ['api.example.com'] });
    expect(() => requireDockerEgress(policy)).not.toThrow();
    expect(() => requireDockerEgress(readPolicy({ egress: { mode: 'managed', allowedDomains: ['api.example.com'] } }))).toThrow(/gateway image/);
  });

  it('loads the restricted domain set from the packaged versioned preset', () => {
    const policy = readPolicy({ egress: { mode: 'managed', gatewayImage: 'gateway@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' } });
    expect(policy.egress.gatewayPolicy.allowedDomains).toEqual([
      'api.anthropic.com', 'api.openai.com', 'api.github.com', 'github.com', '*.githubusercontent.com', 'registry.npmjs.org',
    ]);
  });

  it('rejects egress proxy URLs with credentials', () => {
    expect(() => requireDockerEgress(readPolicy({
      egress: { mode: 'external', proxyUrl: 'http://user:password@proxy.openchamber:3128' },
    }))).toThrow(/must not include credentials/);
  });

  it('rejects invalid Kubernetes egress CIDRs', () => {
    expect(() => requireKubernetesEgress(readPolicy({
      egress: { mode: 'external', proxyUrl: 'http://10.0.0.10:3128', proxyCIDR: 'not-a-cidr', dnsCIDRs: ['10.0.0.53/32'] },
    }))).toThrow(/valid IPv4 or IPv6 CIDR/);
  });
});
