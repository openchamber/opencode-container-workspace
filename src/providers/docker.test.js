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

const { readPolicy } = await import('../policy.js');
const { SECURE_DOCKER_NETWORK } = await import('../policy.js');
const { createDockerProvider } = await import('./docker.js');

describe('docker workspace provider ownership guards', () => {
  beforeEach(() => {
    processMocks.commandExists.mockReturnValue(true);
    processMocks.run.mockReset();
    processMocks.run.mockResolvedValue({ stdout: '', stderr: '' });
    processMocks.runJson.mockReset();
    authMocks.getWorkspaceToken.mockClear();
    authMocks.deleteWorkspaceToken.mockClear();
    healthMocks.waitForHttpHealth.mockClear();
  });

  function createConfiguredWorkspace(id = 'ws:1/abc') {
    const policy = readPolicy({
      defaultImage: 'workspace-image:1.0.0',
      requirePinnedImage: false,
      egress: { httpProxy: 'http://proxy.openchamber:3128', noProxy: '127.0.0.1,localhost' },
    });
    const provider = createDockerProvider({ policy, sourceDirectory: '/source' });
    const info = provider.configure({ id, projectID: 'project:1' });
    expect(info.extra.labels['openchamber.workspace.id']).toBe(canonicalWorkspaceLabelID(id));
    const labels = info.extra.labels;
    return { provider, info, labels };
  }

  it.each(['ws_1', 'ws:1/abc'])('targets workspace ID %s using canonical labels', async (id) => {
    const { provider, info, labels } = createConfiguredWorkspace(id);
    processMocks.runJson
      .mockResolvedValueOnce([{ Config: { Labels: labels } }])
      .mockResolvedValueOnce([{
        State: { Running: true },
        NetworkSettings: { Ports: { '4096/tcp': [{ HostPort: '49123' }] } },
      }]);

    await expect(provider.target(info)).resolves.toEqual({
      type: 'remote',
      url: 'http://127.0.0.1:49123',
      headers: { 'x-openchamber-workspace-token': 'runtime-token' },
    });
  });

  it.each(['ws_1', 'ws:1/abc'])('exports workspace ID %s using canonical labels', async (id) => {
    const { provider, info, labels } = createConfiguredWorkspace(id);
    processMocks.runJson.mockResolvedValueOnce([{ Config: { Labels: labels } }]);
    processMocks.run.mockResolvedValueOnce({ stdout: 'diff --git a/a b/a\n', stderr: '' });

    await expect(provider.exportDiff(info)).resolves.toEqual({ patch: 'diff --git a/a b/a\n', provider: 'docker' });
  });

  it.each(['ws_1', 'ws:1/abc'])('removes workspace ID %s using canonical labels', async (id) => {
    const { provider, info, labels } = createConfiguredWorkspace(id);
    processMocks.runJson
      .mockResolvedValueOnce([{ Config: { Labels: labels } }])
      .mockResolvedValueOnce([{ Labels: labels }]);

    await expect(provider.remove(info)).resolves.toBeUndefined();

    expect(processMocks.run).toHaveBeenCalledWith('docker', ['rm', '-f', info.extra.runtime.container], expect.any(Object));
    expect(processMocks.run).toHaveBeenCalledWith('docker', ['volume', 'rm', info.extra.storage.volume], expect.any(Object));
    expect(authMocks.deleteWorkspaceToken).toHaveBeenCalledWith(info.extra.auth.tokenRef);
  });

  it('reconstructs listed workspaces with the same token ref after restart', async () => {
    const { provider, info, labels } = createConfiguredWorkspace('ws:1/abc');
    processMocks.run.mockResolvedValueOnce({
      stdout: `${JSON.stringify({ Names: info.extra.runtime.container, Labels: Object.entries(labels).map(([key, value]) => `${key}=${value}`).join(',') })}\n`,
      stderr: '',
    });

    const listed = await provider.list({ instance: { project: { id: 'project:1' } } });

    expect(listed).toHaveLength(1);
    expect(listed[0].extra.auth.tokenRef).toBe(info.extra.auth.tokenRef);
    expect(listed[0].extra.runtime.container).toBe(info.extra.runtime.container);
    expect(listed[0].extra.storage.volume).toBe(info.extra.storage.volume);
  });

  it('creates the default owned internal network and starts the runtime container on it', async () => {
    const { provider, info, labels } = createConfiguredWorkspace('ws_1');
    processMocks.runJson
      .mockRejectedValueOnce(new Error('network not found'))
      .mockResolvedValueOnce([{ Config: { Labels: labels } }])
      .mockResolvedValueOnce([{
        State: { Running: true },
        NetworkSettings: { Ports: { '4096/tcp': [{ HostPort: '49123' }] } },
      }]);

    await provider.create(info, { OPENCODE_AUTH_CONTENT: '{}' });

    expect(processMocks.run).toHaveBeenCalledWith('docker', expect.arrayContaining([
      'network', 'create', '--driver', 'bridge', '--internal', SECURE_DOCKER_NETWORK,
    ]), expect.any(Object));
    const runtimeRun = processMocks.run.mock.calls.find(([, args]) => args[0] === 'run' && args.includes('-d'));
    expect(runtimeRun?.[1]).toContain('--network');
    expect(runtimeRun?.[1]).toContain(SECURE_DOCKER_NETWORK);
    expect(runtimeRun?.[1]).toContain('-e');
    expect(runtimeRun?.[1]).toContain('HTTPS_PROXY=http://proxy.openchamber:3128');
    const helperRuns = processMocks.run.mock.calls.filter(([, args]) => args[0] === 'run' && args.includes('--rm') && !args.includes('-d'));
    expect(helperRuns).toHaveLength(2);
    expect(helperRuns[0]?.[1]).toContain('-i');
    for (const [, args] of helperRuns) {
      expect(args).toContain('--network');
      expect(args).toContain('none');
      expect(args).toContain('--security-opt');
      expect(args).toContain('no-new-privileges');
      expect(args).toContain('--cap-drop');
      expect(args).toContain('ALL');
    }
    expect(healthMocks.waitForHttpHealth).toHaveBeenCalledWith('http://127.0.0.1:49123', { 'x-openchamber-workspace-token': 'runtime-token' });
  });

  it('rejects default secure network creation without an explicit egress proxy', async () => {
    const policy = readPolicy({ defaultImage: 'workspace-image:1.0.0', requirePinnedImage: false });
    const provider = createDockerProvider({ policy, sourceDirectory: '/source' });
    const info = provider.configure({ id: 'ws_1', projectID: 'project:1' });

    await expect(provider.create(info, { OPENCODE_AUTH_CONTENT: '{}' })).rejects.toThrow(/require.*egress/i);
    expect(processMocks.run).not.toHaveBeenCalled();
  });
});
