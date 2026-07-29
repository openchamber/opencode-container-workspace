import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const processMocks = vi.hoisted(() => ({ commandExists: vi.fn(() => true), run: vi.fn(), runJson: vi.fn() }));
vi.mock('../process.js', async (importOriginal) => ({ ...await importOriginal(), ...processMocks }));
const { createWorkspaceSecrets, getWorkspaceToken } = await import('../auth.js');
const { providerLabels } = await import('../metadata.js');
const { readPolicy } = await import('../policy.js');
const { readWorkspaceState, writeWorkspaceState } = await import('../state-store.js');
const { createAppleContainerProvider } = await import('./apple-container.js');

describe('Apple Container provider contracts', () => {
  let stateDirectory;
  beforeEach(async () => {
    stateDirectory = await mkdtemp(join(tmpdir(), 'workspace-apple-container-test-'));
    process.env.OPENCHAMBER_WORKSPACE_STATE_DIR = stateDirectory;
    processMocks.commandExists.mockReturnValue(true);
    processMocks.run.mockReset().mockResolvedValue({ stdout: '', stderr: '' });
    processMocks.runJson.mockReset();
  });
  afterEach(async () => {
    vi.unstubAllGlobals();
    delete process.env.OPENCHAMBER_WORKSPACE_STATE_DIR;
    await rm(stateDirectory, { recursive: true, force: true });
  });

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

  it('treats generic Apple delete failures as success after confirming absence', async () => {
    const image = 'workspace-image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    const policy = readPolicy({ defaultImage: image, egress: { mode: 'external', proxyUrl: 'http://127.0.0.1:3128' } });
    const provider = createAppleContainerProvider({ policy, sourceDirectory: '/source' });
    const info = provider.configure({ id: 'control-id', projectID: 'project-id' });
    const identity = { provider: 'apple-container', providerResourceID: info.extra.providerResourceID, projectID: 'project-id', controlPlaneWorkspaceID: 'control-id', originalControlPlaneWorkspaceID: 'control-id' };
    await writeWorkspaceState(info.extra.providerResourceID, { version: 1, ...identity, lifecycle: 'failed' });
    processMocks.runJson.mockRejectedValue(new Error('resource not found'));
    processMocks.run.mockRejectedValue(new Error('failed to delete one or more resources'));

    await expect(provider.remove(info)).resolves.toMatchObject({ ok: true, remainingResources: [] });
    expect(await readWorkspaceState(info.extra.providerResourceID)).toBeNull();
  });

  it('restores credentials and recreates the runtime when a detached secret update fails', async () => {
    const image = 'workspace-image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    const policy = readPolicy({ defaultImage: image, egress: { mode: 'external', proxyUrl: 'http://proxy:3128' } });
    const provider = createAppleContainerProvider({ policy, sourceDirectory: '/source' });
    const info = provider.configure({ id: 'control-id', projectID: 'project-id' });
    const identity = { provider: 'apple-container', providerResourceID: info.extra.providerResourceID, projectID: 'project-id', controlPlaneWorkspaceID: 'control-id', originalControlPlaneWorkspaceID: 'control-id' };
    const roles = new Map([
      [info.extra.resourceRefs.runtime, 'runtime'],
      [info.extra.resourceRefs.mutableVolume, 'mutable-storage'],
      [info.extra.resourceRefs.baselineVolume, 'baseline-storage'],
      [info.extra.resourceRefs.secretVolume, 'secrets'],
      [info.extra.resourceRefs.network, 'network'],
    ]);
    let runtimeExists = true;
    let secretUpdates = 0;
    processMocks.runJson.mockImplementation(async (_binary, args) => {
      const name = args.at(-1);
      if (name === info.extra.resourceRefs.runtime && !runtimeExists) throw new Error('container not found');
      const role = roles.get(name);
      const entry = { configuration: { labels: providerLabels(identity, role) } };
      if (role === 'runtime') Object.assign(entry, { status: { state: 'running' }, configuration: { ...entry.configuration, publishedPorts: [{ containerPort: 4096, hostAddress: '127.0.0.1', hostPort: 55123 }] } });
      if (role === 'network') Object.assign(entry, { configuration: { ...entry.configuration, mode: 'hostOnly' }, status: { ipv4Gateway: '192.168.64.1' } });
      return [entry];
    });
    processMocks.run.mockImplementation(async (_binary, args) => {
      if (args[0] === 'delete') runtimeExists = false;
      if (args[0] === 'run' && args.includes(info.extra.resourceRefs.secretVolume + ':/run/openchamber-workspace')) {
        secretUpdates += 1;
        if (secretUpdates === 1) throw new Error('secret update failed');
      } else if (args[0] === 'run' && args.includes(info.extra.resourceRefs.runtime)) runtimeExists = true;
      return { stdout: '', stderr: '' };
    });
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{}', { status: 200 })));
    await createWorkspaceSecrets(info.extra.providerResourceID);
    const previousToken = await getWorkspaceToken(info.extra.authRef);
    await writeWorkspaceState(info.extra.providerResourceID, { version: 1, ...identity, lifecycle: 'ready', hostPort: 55123, imageDigest: image });

    await expect(provider.rotateCredentials(info)).rejects.toThrow('secret update failed');

    expect(await getWorkspaceToken(info.extra.authRef)).toBe(previousToken);
    expect(runtimeExists).toBe(true);
    expect(secretUpdates).toBe(2);
    const secretCommands = processMocks.run.mock.calls.map(([, args]) => args).filter((args) => args.includes(info.extra.resourceRefs.secretVolume + ':/run/openchamber-workspace'));
    expect(secretCommands).toHaveLength(2);
    for (const command of secretCommands) {
      expect(command).toEqual(expect.arrayContaining(['--user', '1000:1000', '--network', 'none', '--cap-drop', 'ALL']));
      expect(command).not.toContain('--cap-add');
    }
    const deleteIndex = processMocks.run.mock.calls.findIndex(([, args]) => args[0] === 'delete');
    const restoreIndex = processMocks.run.mock.calls.findLastIndex(([, args]) => args.includes(info.extra.resourceRefs.secretVolume + ':/run/openchamber-workspace'));
    const recreateIndex = processMocks.run.mock.calls.findLastIndex(([, args]) => args[0] === 'run' && args.includes(info.extra.resourceRefs.runtime));
    expect(deleteIndex).toBeLessThan(restoreIndex);
    expect(restoreIndex).toBeLessThan(recreateIndex);
  });
});
