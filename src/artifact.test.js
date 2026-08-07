import { describe, expect, it } from 'vitest';
import { chmod, mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { finalizeArtifact, RUNTIME_ARTIFACT_SCRIPT } from './artifact.js';
import { runJson } from './process.js';

describe('structured export artifacts', () => {
  it('binds identity, expiration, files, blobs, and integrity', () => {
    const artifact = finalizeArtifact({ version: 1, baselineGeneration: 'generation', files: [{ id: 'file', kind: 'add', binary: true }], blobs: [{ hash: 'hash', contentBase64: 'AA==' }] }, { controlPlaneWorkspaceID: 'control', providerResourceID: 'resource', projectID: 'project', provider: 'docker' }, '/trusted/project', 1000);
    expect(artifact).toMatchObject({ version: 1, controlPlaneWorkspaceID: 'control', providerResourceID: 'resource', targetDirectory: '/trusted/project', baselineGeneration: 'generation' });
    expect(artifact.integrityHash).toMatch(/^[a-f0-9]{64}$/);
    expect(Date.parse(artifact.expiresAt)).toBeGreaterThan(Date.parse(artifact.createdAt));
  });

  it('models rename, mode, symlink, binary, add, modification, and deletion for non-Git trees', async () => {
    const root = await mkdtemp(join(tmpdir(), 'artifact-runtime-test-'));
    const baseline = join(root, 'baseline');
    const workspace = join(root, 'workspace');
    await mkdir(baseline); await mkdir(workspace);
    await writeFile(join(baseline, 'rename-old'), 'same');
    await writeFile(join(workspace, 'rename-new'), 'same');
    await writeFile(join(baseline, 'mode'), 'mode'); await writeFile(join(workspace, 'mode'), 'mode'); await chmod(join(workspace, 'mode'), 0o755);
    await symlink('old', join(baseline, 'link')); await symlink('new', join(workspace, 'link'));
    await writeFile(join(baseline, 'modify'), 'before'); await writeFile(join(workspace, 'modify'), 'after');
    await writeFile(join(baseline, 'delete'), 'gone');
    await writeFile(join(workspace, 'binary'), Buffer.from([0, 255, 1]));
    try {
      const snapshot = await runJson(process.execPath, ['-e', RUNTIME_ARTIFACT_SCRIPT, baseline, workspace, 'generation', '1048576', '1048576', '10485760'], { sensitiveValues: [RUNTIME_ARTIFACT_SCRIPT] });
      // A mode change can only be detected where modes change. Windows reports the same
      // mode before and after `chmod`, so the operation legitimately does not appear.
      const expectedKinds = process.platform === 'win32'
        ? ['rename', 'modify', 'delete', 'add']
        : ['rename', 'mode', 'modify', 'delete', 'add'];
      expect(snapshot.files.map((file) => file.kind)).toEqual(expect.arrayContaining(expectedKinds));
      expect(snapshot.files.find((file) => file.newPath === 'binary')).toMatchObject({ binary: true, kind: 'add' });
      expect(snapshot.files.find((file) => file.newPath === 'link')).toMatchObject({ symlinkTarget: 'new' });
      expect(snapshot.files.find((file) => file.newPath === 'modify').textHunks).toHaveLength(1);
      expect(snapshot.files.find((file) => file.newPath === 'binary').textHunks).toEqual([]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('omits parent directory operations for added and deleted trees but preserves empty directories', async () => {
    const root = await mkdtemp(join(tmpdir(), 'artifact-directory-test-'));
    const baseline = join(root, 'baseline');
    const workspace = join(root, 'workspace');
    await mkdir(join(baseline, 'deleted', 'nested'), { recursive: true });
    await writeFile(join(baseline, 'deleted', 'nested', 'file'), 'old');
    await mkdir(join(baseline, 'empty-deleted'));
    await mkdir(join(workspace, 'added', 'nested'), { recursive: true });
    await writeFile(join(workspace, 'added', 'nested', 'file'), 'new');
    await mkdir(join(workspace, 'empty-added'));
    try {
      const snapshot = await runtimeSnapshot(baseline, workspace);
      expect(snapshot.files.filter((file) => file.newPath?.startsWith('added/'))).toEqual([expect.objectContaining({ kind: 'add', newPath: 'added/nested/file' })]);
      expect(snapshot.files.filter((file) => file.oldPath?.startsWith('deleted/'))).toEqual([expect.objectContaining({ kind: 'delete', oldPath: 'deleted/nested/file' })]);
      expect(snapshot.files).toEqual(expect.arrayContaining([
        expect.objectContaining({ kind: 'add', newPath: 'empty-added', next: expect.objectContaining({ type: 'directory' }) }),
        expect.objectContaining({ kind: 'delete', oldPath: 'empty-deleted', old: expect.objectContaining({ type: 'directory' }) }),
      ]));
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('matches exact file and symlink renames one-to-one and never infers directory renames', async () => {
    const root = await mkdtemp(join(tmpdir(), 'artifact-rename-test-'));
    const baseline = join(root, 'baseline');
    const workspace = join(root, 'workspace');
    await mkdir(baseline); await mkdir(workspace);
    await writeFile(join(baseline, 'old-one'), 'duplicate');
    await writeFile(join(baseline, 'old-two'), 'duplicate');
    await writeFile(join(workspace, 'new-one'), 'duplicate');
    await symlink('target', join(baseline, 'old-link'));
    await symlink('target', join(workspace, 'new-link'));
    await mkdir(join(baseline, 'old-empty'));
    await mkdir(join(workspace, 'new-empty'));
    try {
      const snapshot = await runtimeSnapshot(baseline, workspace);
      const duplicateChanges = snapshot.files.filter((file) => ['old-one', 'old-two'].includes(file.oldPath));
      expect(duplicateChanges.filter((file) => file.kind === 'rename')).toHaveLength(1);
      expect(duplicateChanges.filter((file) => file.kind === 'delete')).toHaveLength(1);
      expect(snapshot.files.filter((file) => file.newPath === 'new-one')).toHaveLength(1);
      expect(snapshot.files).toContainEqual(expect.objectContaining({ kind: 'rename', oldPath: 'old-link', newPath: 'new-link', symlinkTarget: 'target' }));
      expect(snapshot.files.find((file) => file.oldPath === 'old-empty')).toMatchObject({ kind: 'delete' });
      expect(snapshot.files.find((file) => file.newPath === 'new-empty')).toMatchObject({ kind: 'add' });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('limits exported blobs instead of unchanged source content', async () => {
    const root = await mkdtemp(join(tmpdir(), 'artifact-limit-test-'));
    const baseline = join(root, 'baseline');
    const workspace = join(root, 'workspace');
    await mkdir(baseline); await mkdir(workspace);
    const unchanged = 'unchanged source content';
    await writeFile(join(baseline, 'unchanged'), unchanged);
    await writeFile(join(workspace, 'unchanged'), unchanged);
    await writeFile(join(workspace, 'added'), 'ok');
    try {
      const snapshot = await runJson(process.execPath, ['-e', RUNTIME_ARTIFACT_SCRIPT, baseline, workspace, 'generation', '100', '100', '10'], { sensitiveValues: [RUNTIME_ARTIFACT_SCRIPT] });
      expect(snapshot.files).toEqual([expect.objectContaining({ kind: 'add', newPath: 'added' })]);
      expect(snapshot.totalBytes).toBe(2);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('rejects artifacts whose changed blobs exceed the total limit', async () => {
    const root = await mkdtemp(join(tmpdir(), 'artifact-changed-limit-test-'));
    const baseline = join(root, 'baseline');
    const workspace = join(root, 'workspace');
    await mkdir(baseline); await mkdir(workspace);
    await writeFile(join(baseline, 'modified'), 'before');
    await writeFile(join(workspace, 'modified'), 'after!');
    try {
      await expect(runJson(process.execPath, ['-e', RUNTIME_ARTIFACT_SCRIPT, baseline, workspace, 'generation', '100', '100', '10'], { sensitiveValues: [RUNTIME_ARTIFACT_SCRIPT] })).rejects.toThrow(/failed with 1/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

function runtimeSnapshot(baseline, workspace) {
  return runJson(process.execPath, ['-e', RUNTIME_ARTIFACT_SCRIPT, baseline, workspace, 'generation', '1048576', '1048576', '10485760'], { sensitiveValues: [RUNTIME_ARTIFACT_SCRIPT] });
}
