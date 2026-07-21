import { describe, expect, it, vi, beforeEach } from 'vitest';
import { canonicalWorkspaceLabelID } from '../label-id.js';

const processMocks = vi.hoisted(() => ({
  commandExists: vi.fn(() => true),
  run: vi.fn(),
  runJson: vi.fn(),
}));

const authMocks = vi.hoisted(() => ({
  createWorkspaceToken: vi.fn(async (id) => ({ token: `token-${id}` })),
  deleteWorkspaceToken: vi.fn(async () => undefined),
  getWorkspaceToken: vi.fn(async () => 'runtime-token'),
}));

const healthMocks = vi.hoisted(() => ({
  waitForHttpHealth: vi.fn(async () => undefined),
}));

vi.mock('../process.js', async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual,
    commandExists: processMocks.commandExists,
    run: processMocks.run,
    runJson: processMocks.runJson,
  };
});

vi.mock('../auth.js', async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, ...authMocks };
});

vi.mock('../health.js', () => healthMocks);

const { readPolicy, SECURE_APPLE_CONTAINER_NETWORK } = await import('../policy.js');
const { createAppleContainerProvider } = await import('./apple-container.js');

describe('Apple Container workspace provider', () => {
  beforeEach(() => {
    processMocks.commandExists.mockReturnValue(true);
    processMocks.run.mockReset();
    processMocks.run.mockResolvedValue({ stdout: '', stderr: '' });
    processMocks.runJson.mockReset();
    authMocks.deleteWorkspaceToken.mockClear();
    healthMocks.waitForHttpHealth.mockClear();
  });

  function createConfiguredWorkspace(id = 'ws:1/abc') {
    const policy = readPolicy({
      defaultImage: 'workspace-image:1.0.0',
      requirePinnedImage: false,
      egress: { httpProxy: 'http://127.0.0.1:3128', noProxy: '127.0.0.1,localhost' },
      appleContainer: { cli: '/usr/local/bin/container' },
    });
    const provider = createAppleContainerProvider({ policy, sourceDirectory: '/source' });
    const info = provider.configure({ id, projectID: 'project:1' });
    expect(info.extra.labels['openchamber.workspace.id']).toBe(canonicalWorkspaceLabelID(id));
    return { provider, info, labels: info.extra.labels };
  }

  it('targets a loopback-published runtime using container inspect', async () => {
    const { provider, info, labels } = createConfiguredWorkspace();
    processMocks.runJson
      .mockResolvedValueOnce([{ configuration: { labels } }])
      .mockResolvedValueOnce([{
        id: info.extra.runtime.container,
        status: { state: 'running' },
        configuration: { publishedPorts: [{ hostAddress: '127.0.0.1', hostPort: 49197, containerPort: 4096 }] },
      }]);

    await expect(provider.target(info)).resolves.toEqual({
      type: 'remote',
      url: 'http://127.0.0.1:49197',
      headers: { 'x-openchamber-workspace-token': 'runtime-token' },
    });
  });

  it('creates an internal host-only network and starts runtime with loopback publish', async () => {
    const { provider, info, labels } = createConfiguredWorkspace('ws_1');
    processMocks.runJson
      .mockRejectedValueOnce(new Error('network not found'))
      .mockResolvedValueOnce([{ status: { ipv4Gateway: '192.168.129.1' } }])
      .mockResolvedValueOnce([{ configuration: { labels } }])
      .mockResolvedValueOnce([{
        id: info.extra.runtime.container,
        status: { state: 'running' },
        configuration: { publishedPorts: [{ hostAddress: '127.0.0.1', hostPort: info.extra.runtime.hostPort, containerPort: 4096 }] },
      }]);

    await provider.create(info, { OPENCODE_AUTH_CONTENT: '{}' });

    expect(processMocks.run).toHaveBeenCalledWith('/usr/local/bin/container', expect.arrayContaining([
      'network', 'create', '--internal', SECURE_APPLE_CONTAINER_NETWORK,
    ]), expect.any(Object));
    const runtimeRun = processMocks.run.mock.calls.find(([, args]) => args[0] === 'run' && args.includes('--detach'));
    expect(runtimeRun?.[0]).toBe('/usr/local/bin/container');
    expect(runtimeRun?.[1]).toContain('--network');
    expect(runtimeRun?.[1]).toContain(SECURE_APPLE_CONTAINER_NETWORK);
    expect(runtimeRun?.[1]).toContain('--cap-drop');
    expect(runtimeRun?.[1]).toContain('ALL');
    expect(runtimeRun?.[1]).toContain('--publish');
    expect(runtimeRun?.[1]).toContain(`127.0.0.1:${info.extra.runtime.hostPort}:4096`);
    expect(runtimeRun?.[1]).toContain('HTTPS_PROXY=http://192.168.129.1:3128/');
    expect(healthMocks.waitForHttpHealth).toHaveBeenCalledWith(`http://127.0.0.1:${info.extra.runtime.hostPort}`, { 'x-openchamber-workspace-token': 'runtime-token' }, { timeoutMs: 90_000 });
  });

  it('rejects secure Apple Container workspaces without an explicit egress proxy', async () => {
    const policy = readPolicy({
      defaultImage: 'workspace-image:1.0.0',
      requirePinnedImage: false,
      appleContainer: { cli: '/usr/local/bin/container' },
    });
    const provider = createAppleContainerProvider({ policy, sourceDirectory: '/source' });
    const info = provider.configure({ id: 'ws_1', projectID: 'project:1' });

    await expect(provider.create(info, { OPENCODE_AUTH_CONTENT: '{}' })).rejects.toThrow(/require.*egress/i);
    expect(processMocks.run).not.toHaveBeenCalled();
  });
});
