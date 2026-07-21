import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { SECURE_DOCKER_NETWORK, readPolicy, requireDockerEgress, requireKubernetesEgress } from './policy.js';

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
    expect(readPolicy().docker).toMatchObject({ networkMode: SECURE_DOCKER_NETWORK, allowedNetworks: [] });
  });

  it('rejects connected Docker networks unless explicitly allowed', () => {
    expect(() => readPolicy({ docker: { networkMode: 'bridge' } })).toThrow(/Docker network mode is not allowed/);
    expect(readPolicy({ docker: { networkMode: 'bridge', allowedNetworks: ['bridge'] } }).docker.networkMode).toBe('bridge');
  });

  it('rejects Kubernetes restricted NetworkPolicy until explicit selectors are supported', () => {
    expect(() => readPolicy({ kubernetes: { networkPolicy: 'restricted' } })).toThrow(/requires explicit allowed selectors/);
  });

  it('uses default-deny Kubernetes NetworkPolicy by default', () => {
    expect(readPolicy().kubernetes.networkPolicy).toBe('default-deny');
  });

  it('requires explicit Docker egress proxy for the owned internal network', () => {
    expect(() => requireDockerEgress(readPolicy())).toThrow(/egress/i);
    expect(() => requireDockerEgress(readPolicy({ egress: { httpProxy: 'http://proxy.openchamber:3128' } }))).not.toThrow();
  });

  it('requires explicit Kubernetes proxy and DNS egress for default-deny policy', () => {
    expect(() => requireKubernetesEgress(readPolicy())).toThrow(/egress/i);
    expect(() => requireKubernetesEgress(readPolicy({
      egress: { httpProxy: 'http://10.0.0.10:3128', proxyCIDR: '10.0.0.10/32', dnsCIDRs: ['10.0.0.53/32'] },
    }))).not.toThrow();
  });

  it('rejects egress proxy URLs with credentials', () => {
    expect(() => requireDockerEgress(readPolicy({
      egress: { httpProxy: 'http://user:password@proxy.openchamber:3128' },
    }))).toThrow(/must not include credentials/);
  });

  it('rejects invalid Kubernetes egress CIDRs', () => {
    expect(() => requireKubernetesEgress(readPolicy({
      egress: { httpProxy: 'http://10.0.0.10:3128', proxyCIDR: 'not-a-cidr', dnsCIDRs: ['10.0.0.53/32'] },
    }))).toThrow(/valid IPv4 or IPv6 CIDR/);
  });
});
