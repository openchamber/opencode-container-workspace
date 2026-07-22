import { describe, expect, it } from 'vitest';
import { readPolicy } from '../policy.js';
import { createAppleContainerProvider } from './apple-container.js';

describe('Apple Container provider contracts', () => {
  it('uses canonical per-workspace host-only network and baseline storage metadata', () => {
    const policy = readPolicy({ defaultImage: 'workspace-image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', egress: { mode: 'external', proxyUrl: 'http://127.0.0.1:3128' } });
    const provider = createAppleContainerProvider({ policy, sourceDirectory: '/source' });
    const info = provider.configure({ id: 'control-id', projectID: 'project-id' });
    expect(info.extra.provider).toBe('apple-container');
    expect(info.extra.resourceRefs.network).toContain(info.extra.providerResourceID);
    expect(info.extra.resourceRefs.baselineVolume).toMatch(/baseline$/);
  });

  it('rejects unsupported secret modes and connected default networks', () => {
    expect(() => readPolicy({ secrets: { mode: 'environment' } })).toThrow(/provider-backed files/);
  });
});
