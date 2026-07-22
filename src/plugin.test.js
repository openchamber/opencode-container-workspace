import { describe, expect, it, vi } from 'vitest';
import plugin from './plugin.js';

describe('openchamber workspace plugin', () => {
  it('no-ops on OpenCode versions without the experimental workspace registry', async () => {
    const result = await plugin({ directory: '/repo' });

    expect(result.openchamber.secureWorkspaces).toEqual({
      registered: false,
      reason: 'OpenCode experimental workspace API is not available',
    });
  });

  it('registers Docker, Kubernetes, and Apple Container adapters when the workspace registry is available', async () => {
    const register = vi.fn();
    const result = await plugin({ directory: '/repo', experimental_workspace: { register } });

    expect(result.openchamber.secureWorkspaces.registered).toBe(true);
    expect(register).toHaveBeenCalledWith('docker', expect.objectContaining({ name: 'Docker' }));
    expect(register).toHaveBeenCalledWith('kubernetes', expect.objectContaining({ name: 'Kubernetes' }));
    expect(register).toHaveBeenCalledWith('apple-container', expect.objectContaining({ name: 'Apple Container' }));
    for (const [, adapter] of register.mock.calls) expect(adapter).not.toHaveProperty('exportDiff');
  });
});
