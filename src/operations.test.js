import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const provider = vi.hoisted(() => ({
  kind: 'docker',
  validate: vi.fn(),
  list: vi.fn(),
  health: vi.fn(),
  remove: vi.fn(async () => ({ ok: true, remainingResources: [], diagnostics: [] })),
  reconcile: vi.fn(async () => ({ status: 'ready', diagnostics: [] })),
  rotateCredentials: vi.fn(),
  exportWorkspace: vi.fn(async () => ({ version: 1, baselineGeneration: 'generation', files: [], blobs: [] })),
}));
vi.mock('./providers/docker.js', () => ({ createDockerProvider: () => provider }));
vi.mock('./providers/kubernetes.js', () => ({ createKubernetesProvider: () => ({ ...provider, kind: 'kubernetes' }) }));
vi.mock('./providers/apple-container.js', () => ({ createAppleContainerProvider: () => ({ ...provider, kind: 'apple-container' }) }));

const { createWorkspaceProviderOperations } = await import('./operations.js');
const { readPolicy } = await import('./policy.js');
const { canonicalResourceRefs, createMetadata } = await import('./metadata.js');
const { readWorkspaceState, writeWorkspaceState } = await import('./state-store.js');

describe('workspace provider recovery operations', () => {
  let stateDirectory;
  let sourceDirectory;
  let policy;

  beforeEach(async () => {
    stateDirectory = await mkdtemp(join(tmpdir(), 'workspace-operations-state-'));
    sourceDirectory = await mkdtemp(join(tmpdir(), 'workspace-operations-source-'));
    process.env.OPENCHAMBER_WORKSPACE_STATE_DIR = stateDirectory;
    policy = readPolicy({ defaultImage: `image@sha256:${'a'.repeat(64)}` });
    for (const mock of [provider.list, provider.remove, provider.reconcile, provider.exportWorkspace]) mock.mockReset();
    provider.reconcile.mockResolvedValue({ status: 'ready', diagnostics: [] });
    provider.remove.mockResolvedValue({ ok: true, remainingResources: [], diagnostics: [] });
    provider.exportWorkspace.mockResolvedValue({ version: 1, baselineGeneration: 'generation', files: [], blobs: [] });
  });

  afterEach(async () => {
    delete process.env.OPENCHAMBER_WORKSPACE_STATE_DIR;
    await Promise.all([rm(stateDirectory, { recursive: true, force: true }), rm(sourceDirectory, { recursive: true, force: true })]);
  });

  function recoveredWorkspace(overrides = {}) {
    const identity = {
      provider: 'docker',
      providerResourceID: 'ws-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      projectID: 'project-1',
      controlPlaneWorkspaceID: 'original-id',
      originalControlPlaneWorkspaceID: 'original-id',
    };
    return {
      id: 'recovered-id',
      type: 'docker',
      projectID: 'project-1',
      extra: createMetadata(
        { id: identity.controlPlaneWorkspaceID, projectID: identity.projectID },
        'docker',
        policy,
        canonicalResourceRefs(identity.providerResourceID, 'docker', policy),
        identity,
      ),
      ...overrides,
    };
  }

  async function seedState(workspace = recoveredWorkspace()) {
    await writeWorkspaceState(workspace.extra.providerResourceID, {
      version: 1,
      provider: workspace.extra.provider,
      providerResourceID: workspace.extra.providerResourceID,
      projectID: workspace.extra.projectID,
      controlPlaneWorkspaceID: workspace.extra.controlPlaneWorkspaceID,
      lifecycle: 'ready',
    });
  }

  it('verifies the original identity before atomically adopting a recovered control-plane ID', async () => {
    const workspace = recoveredWorkspace();
    await seedState(workspace);
    const operations = createWorkspaceProviderOperations({ policy, sourceDirectory });

    const adopted = await operations.adoptWorkspace(workspace);

    expect(provider.reconcile).toHaveBeenCalledWith(expect.objectContaining({ id: 'recovered-id', extra: expect.objectContaining({ controlPlaneWorkspaceID: 'original-id' }) }));
    expect(adopted.extra).toMatchObject({ controlPlaneWorkspaceID: 'recovered-id', originalControlPlaneWorkspaceID: 'original-id', providerResourceID: workspace.extra.providerResourceID });
    expect(await readWorkspaceState(workspace.extra.providerResourceID)).toMatchObject({ controlPlaneWorkspaceID: 'recovered-id', originalControlPlaneWorkspaceID: 'original-id', projectID: 'project-1', provider: 'docker' });
  });

  it('rejects forged provider resource and project recovery metadata before provider verification', async () => {
    const workspace = recoveredWorkspace();
    await seedState(workspace);
    const operations = createWorkspaceProviderOperations({ policy, sourceDirectory });
    const forgedResource = { ...workspace, extra: { ...workspace.extra, providerResourceID: 'ws-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' } };
    const forgedProject = { ...workspace, projectID: 'project-2' };

    await expect(operations.adoptWorkspace(forgedResource)).rejects.toThrow(/state identity mismatch/);
    await expect(operations.adoptWorkspace(forgedProject)).rejects.toThrow(/project identity/);
    expect(provider.reconcile).not.toHaveBeenCalled();
  });

  it('binds exports and cleanup to the recovered current ID while retaining provider ownership', async () => {
    const workspace = recoveredWorkspace();
    await seedState(workspace);
    const operations = createWorkspaceProviderOperations({ policy, sourceDirectory });

    const artifact = await operations.exportWorkspace(workspace);
    const cleanup = await operations.cleanupWorkspace(workspace);

    expect(artifact).toMatchObject({ controlPlaneWorkspaceID: 'recovered-id', providerResourceID: workspace.extra.providerResourceID, projectID: 'project-1', provider: 'docker' });
    expect(provider.remove).toHaveBeenCalledWith(expect.objectContaining({ id: 'recovered-id', extra: expect.objectContaining({ controlPlaneWorkspaceID: 'recovered-id', originalControlPlaneWorkspaceID: 'original-id' }) }));
    expect(cleanup.ok).toBe(true);
  });

  it('repeats adoption idempotently without changing immutable ownership', async () => {
    const workspace = recoveredWorkspace();
    await seedState(workspace);
    const operations = createWorkspaceProviderOperations({ policy, sourceDirectory });

    await operations.adoptWorkspace(workspace);
    const adoptedAgain = await operations.adoptWorkspace(workspace);

    expect(adoptedAgain.extra).toMatchObject({ controlPlaneWorkspaceID: 'recovered-id', originalControlPlaneWorkspaceID: 'original-id', providerResourceID: workspace.extra.providerResourceID });
    expect(await readWorkspaceState(workspace.extra.providerResourceID)).toMatchObject({ controlPlaneWorkspaceID: 'recovered-id', originalControlPlaneWorkspaceID: 'original-id' });
    expect(provider.reconcile).toHaveBeenCalledTimes(2);
    expect(provider.reconcile).toHaveBeenLastCalledWith(expect.objectContaining({ extra: expect.objectContaining({ controlPlaneWorkspaceID: 'recovered-id', originalControlPlaneWorkspaceID: 'original-id' }) }));
  });

  it('keeps provider discovery partial failures explicit', async () => {
    provider.list
      .mockResolvedValueOnce([{ type: 'docker' }])
      .mockRejectedValueOnce(Object.assign(new Error('cluster unavailable'), { code: 'KUBE_UNAVAILABLE' }))
      .mockResolvedValueOnce([{ type: 'apple-container' }]);
    const operations = createWorkspaceProviderOperations({ policy, sourceDirectory });

    const result = await operations.discoverProject('project-1');

    expect(result.workspaces).toEqual([{ type: 'docker' }, { type: 'apple-container' }]);
    expect(result.completeProviders).toEqual(['docker', 'apple-container']);
    expect(result.failures).toEqual([{ provider: 'kubernetes', message: 'cluster unavailable', code: 'KUBE_UNAVAILABLE' }]);
  });
});
