import { describe, expect, it } from 'vitest';
import { grantedEgressPolicy, grantedProviderDomains } from './egress-domains.js';
import { readPolicy } from './policy.js';

const policyWith = (overrides = {}) => readPolicy({ defaultImage: `image@sha256:${'a'.repeat(64)}`, ...overrides });

describe('granted provider egress domains', () => {
  it('derives endpoints for the providers present in the auth payload', () => {
    const domains = grantedProviderDomains(JSON.stringify({ anthropic: { type: 'api', key: 'secret' }, 'opencode-go': { type: 'api', key: 'secret' } }));
    expect(domains).toContain('api.anthropic.com');
    expect(domains).toContain('opencode.ai');
    expect(domains).not.toContain('api.openai.com');
  });

  it('never surfaces credential values and tolerates malformed payloads', () => {
    expect(grantedProviderDomains(JSON.stringify({ anthropic: { key: 'secret-value' } })).join(' ')).not.toContain('secret-value');
    expect(grantedProviderDomains('not json')).toEqual([]);
    expect(grantedProviderDomains(JSON.stringify(['anthropic']))).toEqual([]);
    expect(grantedProviderDomains(undefined)).toEqual([]);
  });

  it('ignores unknown providers without failing the workspace', () => {
    expect(grantedProviderDomains(JSON.stringify({ 'some-future-provider': { key: 'x' } }))).toEqual([]);
  });

  it('merges derived domains into the managed gateway policy without mutating the shared policy', () => {
    const policy = policyWith();
    const before = [...policy.egress.gatewayPolicy.allowedDomains];
    const egress = grantedEgressPolicy(policy, { OPENCODE_AUTH_CONTENT: JSON.stringify({ openrouter: { key: 'x' } }) });
    expect(egress.gatewayPolicy.allowedDomains).toContain('openrouter.ai');
    expect(policy.egress.gatewayPolicy.allowedDomains).toEqual(before);
  });

  it('returns the shared policy unchanged when nothing new is derived', () => {
    const policy = policyWith();
    expect(grantedEgressPolicy(policy, {})).toBe(policy.egress);
    expect(grantedEgressPolicy(policy, { OPENCODE_AUTH_CONTENT: JSON.stringify({ anthropic: { key: 'x' } }) })).toBe(policy.egress);
  });

  it('leaves external proxy egress untouched', () => {
    const policy = policyWith({ egress: { mode: 'external', proxyUrl: 'http://proxy.internal:3128', proxyCIDR: '10.0.0.4/32', dnsCIDRs: '10.0.0.53/32' } });
    expect(grantedEgressPolicy(policy, { OPENCODE_AUTH_CONTENT: JSON.stringify({ anthropic: { key: 'x' } }) })).toBe(policy.egress);
  });

  it('ships the model catalog and package registries the runtime needs by default', () => {
    const allowed = policyWith().egress.gatewayPolicy.allowedDomains;
    for (const domain of ['models.dev', 'opencode.ai', 'registry.npmjs.org', 'pypi.org', 'crates.io', 'proxy.golang.org']) {
      expect(allowed).toContain(domain);
    }
  });
});
