import { homedir } from 'node:os';
import { join, parse as parsePath, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { refuseUnsafeSnapshotRoot, resolveSnapshotSource } from './snapshot.js';

/**
 * A snapshot is handed to the runtime, where workspace code executes. Copying a home
 * directory would put SSH keys, cloud credentials and tokens inside it; copying a
 * filesystem root would put every account there. Neither is a project.
 */
describe('snapshot source safety', () => {
  it('refuses the home directory', () => {
    expect(() => refuseUnsafeSnapshotRoot(homedir())).toThrow(/home directory/i);
  });

  it('refuses the home directory however it is written', () => {
    const awkward = join(homedir(), 'projects', '..');
    expect(() => refuseUnsafeSnapshotRoot(awkward)).toThrow(/home directory/i);
  });

  it('refuses a filesystem root', () => {
    expect(() => refuseUnsafeSnapshotRoot(parsePath(resolve(homedir())).root)).toThrow(/filesystem root/i);
  });

  it('accepts an ordinary project directory inside the home directory', () => {
    expect(() => refuseUnsafeSnapshotRoot(join(homedir(), 'projects', 'demo'))).not.toThrow();
  });

  it('applies to the source a create actually resolves, not only to direct callers', () => {
    expect(() => resolveSnapshotSource({ instance: { directory: homedir() } }, '/some/project'))
      .toThrow(/home directory/i);
  });

  it('still refuses the workspace runtime path it already guarded', () => {
    expect(() => resolveSnapshotSource({ instance: { directory: '/workspace' } }, '/some/project'))
      .toThrow(/workspace runtime path/i);
  });
});
