import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run } from './process.js';
import { resetWindowsAclCache } from './windows-acl.js';
import { readWorkspaceSecret, readWorkspaceState, withWorkspaceLock, workspaceStateDirectory, writeWorkspaceSecret, writeWorkspaceState } from './state-store.js';

const icacls = `${process.env.SystemRoot || 'C:\\Windows'}\\System32\\icacls.exe`;

describe('workspace state store', () => {
  let root;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'workspace-state-test-'));
    process.env.OPENCHAMBER_WORKSPACE_STATE_DIR = root;
    if (process.platform === 'win32') {
      // A profile's temporary directory is already private, so a store created there
      // would look protected whether or not the code protects anything. This one is
      // opened to everyone first, and the test can then observe it being closed.
      await run(icacls, [root, '/grant', '*S-1-1-0:(OI)(CI)F', '/q']);
    }
  });
  afterEach(async () => {
    delete process.env.OPENCHAMBER_WORKSPACE_STATE_DIR;
    resetWindowsAclCache();
    await rm(root, { recursive: true, force: true });
  });

  it('writes state and secrets atomically with restrictive modes', async () => {
    const id = 'ws-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    await writeWorkspaceState(id, { version: 1, providerResourceID: id, lifecycle: 'ready' });
    await writeWorkspaceSecret(id, 'endpoint-token', 'secret');
    expect(await readWorkspaceState(id)).toMatchObject({ lifecycle: 'ready' });
    expect(await readWorkspaceSecret(id, 'endpoint-token')).toBe('secret');
    // Each platform is asked about the mechanism that actually restricts the store there:
    // POSIX modes where they are implemented, and the inherited ACL on Windows, which
    // accepts a chmod and honours none of it.
    if (process.platform === 'win32') {
      const secret = join(workspaceStateDirectory(id), 'secrets', 'endpoint-token');
      const icacls = `${process.env.SystemRoot || 'C:\\Windows'}\\System32\\icacls.exe`;
      const { stdout } = await run(icacls, [secret]);
      const granted = stdout.split(/\r?\n/).filter((line) => line.includes(':(')).join('\n');
      expect(granted).not.toMatch(/Everyone|BUILTIN\\Users|Authenticated Users/i);
      expect(granted).toContain(process.env.USERNAME);
    } else {
      expect((await stat(workspaceStateDirectory(id))).mode & 0o777).toBe(0o700);
      expect((await stat(join(workspaceStateDirectory(id), 'state.json'))).mode & 0o777).toBe(0o600);
      expect((await stat(join(workspaceStateDirectory(id), 'secrets', 'endpoint-token'))).mode & 0o777).toBe(0o600);
    }
  });

  it('reports corrupt state instead of treating it as empty', async () => {
    const id = 'ws-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
    await writeWorkspaceState(id, { version: 1, providerResourceID: id });
    await writeFile(join(workspaceStateDirectory(id), 'state.json'), '{broken');
    await expect(readWorkspaceState(id)).rejects.toMatchObject({ code: 'WORKSPACE_STATE_CORRUPT' });
  });

  it('serializes concurrent workspace operations', async () => {
    const id = 'ws-cccccccccccccccccccccccccccccccc';
    const order = [];
    let markStarted;
    let releaseFirst;
    const started = new Promise((resolve) => { markStarted = resolve; });
    const release = new Promise((resolve) => { releaseFirst = resolve; });
    const first = withWorkspaceLock(id, async () => { order.push('first-start'); markStarted(); await release; order.push('first-end'); });
    await started;
    const second = withWorkspaceLock(id, async () => { order.push('second'); });
    releaseFirst();
    await Promise.all([first, second]);
    expect(order).toEqual(['first-start', 'first-end', 'second']);
  });
});
