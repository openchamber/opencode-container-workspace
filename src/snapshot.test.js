import { afterEach, describe, expect, it } from 'vitest';
import { chmod, link, mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createSourceSnapshot, scanSourceTree } from './snapshot.js';
import { run } from './process.js';

describe('safe source snapshots', () => {
  const roots = [];
  afterEach(async () => Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true }))));
  async function fixture() { const root = await mkdtemp(join(tmpdir(), 'source-snapshot-test-')); roots.push(root); return root; }

  it('excludes Git internals while recording source files, modes, and safe symlinks', async () => {
    const root = await fixture();
    await mkdir(join(root, '.git'));
    await writeFile(join(root, '.git', 'index'), 'dirty-index');
    await link(join(root, '.git', 'index'), join(root, '.git', 'COMMIT_EDITMSG'));
    await writeFile(join(root, 'binary.dat'), Buffer.from([0, 1, 2, 3]));
    await writeFile(join(root, 'script.sh'), '#!/bin/sh\n');
    await chmod(join(root, 'script.sh'), 0o755);
    await symlink('script.sh', join(root, 'link'));
    const snapshot = await createSourceSnapshot(root);
    expect(snapshot.entries).toEqual(expect.arrayContaining([expect.objectContaining({ path: 'script.sh', mode: 0o755 }), expect.objectContaining({ path: 'link', type: 'symlink', target: 'script.sh' })]));
    expect(snapshot.entries.some((entry) => entry.path.startsWith('.git/'))).toBe(false);
    const archive = await run('tar', ['-tf', snapshot.archivePath]);
    expect(archive.stdout).not.toContain('.git/');
    expect(snapshot.generation).toMatch(/^[a-f0-9]{64}$/);
    await snapshot.dispose();
  });

  it('stages archives under a caller-selected provider-visible root', async () => {
    const root = await fixture();
    const staging = await fixture();
    await writeFile(join(root, 'file'), 'content');

    const snapshot = await createSourceSnapshot(root, { temporaryRoot: staging });

    expect(snapshot.archivePath.startsWith(`${staging}/openchamber-source-`)).toBe(true);
    await snapshot.dispose();
  });

  it('snapshots hard-linked regular source files', async () => {
    const root = await fixture();
    await writeFile(join(root, 'LICENSE'), 'license');
    await link(join(root, 'LICENSE'), join(root, 'LICENSE.copy'));

    const snapshot = await createSourceSnapshot(root);

    expect(snapshot.entries).toEqual(expect.arrayContaining([
      expect.objectContaining({ path: 'LICENSE', type: 'file' }),
      expect.objectContaining({ path: 'LICENSE.copy', type: 'file' }),
    ]));
    await snapshot.dispose();
  });

  it('detects source mutation while archiving', async () => {
    const root = await fixture();
    await writeFile(join(root, 'file'), 'before');
    await expect(createSourceSnapshot(root, { beforeArchive: () => writeFile(join(root, 'file'), 'after') })).rejects.toThrow(/changed/);
  });

  it('rejects escaping symlinks, reserved paths, and explicit limits', async () => {
    const root = await fixture();
    await symlink('../outside', join(root, 'escape'));
    await expect(scanSourceTree(root)).rejects.toThrow(/escapes/);
    await rm(join(root, 'escape'));
    await mkdir(join(root, '.openchamber'));
    await expect(scanSourceTree(root)).rejects.toThrow(/reserved/);
    await rm(join(root, '.openchamber'), { recursive: true });
    await writeFile(join(root, 'large'), '12345');
    await expect(scanSourceTree(root, { maxEntries: 10, maxBytes: 4, maxFileBytes: 10 })).rejects.toThrow(/exceeds/);
  });
});
