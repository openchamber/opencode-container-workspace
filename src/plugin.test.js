import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => {
  const provider = (kind) => ({
    kind,
    configure: vi.fn((info) => info),
    create: vi.fn(async () => undefined),
    remove: vi.fn(async () => ({ ok: true })),
    target: vi.fn(async () => ({ type: 'remote', url: 'http://127.0.0.1:4096', headers: {} })),
    list: vi.fn(async () => []),
  });
  return {
    providers: {
      docker: provider('docker'),
      kubernetes: provider('kubernetes'),
      'apple-container': provider('apple-container'),
    },
    ensureTransportShim: vi.fn(async () => ({ type: 'remote', url: 'http://127.0.0.1:49152' })),
    closeTransportShim: vi.fn(async () => undefined),
  };
});

vi.mock('./providers/docker.js', () => ({ createDockerProvider: () => mocks.providers.docker }));
vi.mock('./providers/kubernetes.js', () => ({ createKubernetesProvider: () => mocks.providers.kubernetes }));
vi.mock('./providers/apple-container.js', () => ({ createAppleContainerProvider: () => mocks.providers['apple-container'] }));
vi.mock('./transport-shim.js', () => ({ ensureTransportShim: mocks.ensureTransportShim, closeTransportShim: mocks.closeTransportShim }));
vi.mock('./metadata.js', () => ({ readMetadata: (info) => info.extra }));
import plugin from './plugin.js';

describe('openchamber workspace plugin', () => {
  beforeEach(() => {
    mocks.ensureTransportShim.mockReset().mockResolvedValue({ type: 'remote', url: 'http://127.0.0.1:49152' });
    mocks.closeTransportShim.mockClear();
    for (const provider of Object.values(mocks.providers)) {
      provider.create.mockClear();
      provider.remove.mockClear();
      provider.target.mockClear();
    }
  });

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

  it('prewarms the transport shim before adapter create completes', async () => {
    const register = vi.fn();
    await plugin({ directory: '/repo', experimental_workspace: { register } });
    const adapter = register.mock.calls.find(([kind]) => kind === 'apple-container')[1];
    const info = workspaceInfo();

    await adapter.create(info, {}, undefined, {});

    expect(mocks.providers['apple-container'].create).toHaveBeenCalledWith(info, {}, undefined, {});
    expect(mocks.ensureTransportShim).toHaveBeenCalledWith(expect.objectContaining({ identity: info.extra }));
  });

  it('cleans provider resources when transport prewarm fails', async () => {
    const register = vi.fn();
    await plugin({ directory: '/repo', experimental_workspace: { register } });
    const adapter = register.mock.calls.find(([kind]) => kind === 'apple-container')[1];
    const info = workspaceInfo();
    mocks.ensureTransportShim.mockRejectedValueOnce(new Error('shim failed'));

    await expect(adapter.create(info, {}, undefined, {})).rejects.toThrow('shim failed');
    expect(mocks.providers['apple-container'].remove).toHaveBeenCalledWith(info, {});
  });
});

function workspaceInfo() {
  return {
    id: 'wrk_control',
    projectID: 'project-id',
    extra: {
      provider: 'apple-container',
      providerResourceID: `ws-${'a'.repeat(32)}`,
      projectID: 'project-id',
      controlPlaneWorkspaceID: 'wrk_control',
    },
  };
}
