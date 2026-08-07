import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readWorkspaceSecret, readWorkspaceState, withWorkspaceLock, workspaceStateDirectory, writeWorkspaceSecret, writeWorkspaceState } from './state-store.js';

describe('workspace state store', () => {
  let root;
  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'workspace-state-test-'));
    process.env.OPENCHAMBER_WORKSPACE_STATE_DIR = root;
  });
  afterEach(async () => {
    delete process.env.OPENCHAMBER_WORKSPACE_STATE_DIR;
    await rm(root, { recursive: true, force: true });
  });

  it('writes state and secrets atomically with restrictive modes', async () => {
    const id = 'ws-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    await writeWorkspaceState(id, { version: 1, providerResourceID: id, lifecycle: 'ready' });
    await writeWorkspaceSecret(id, 'endpoint-token', 'secret');
    expect(await readWorkspaceState(id)).toMatchObject({ lifecycle: 'ready' });
    expect(await readWorkspaceSecret(id, 'endpoint-token')).toBe('secret');
    // POSIX modes are how this store restricts its state and secrets, and Windows does
    // not implement them: `chmod` is close to a no-op there and every file reports 0o666.
    // Asserting the modes on Windows would only restate that, so the check is skipped —
    // but the protection genuinely is absent there, standing only on ACLs inherited from
    // wherever the data directory happens to live. Enforcing it explicitly on Windows is
    // outstanding work, not a platform difference that can be waved through.
    if (process.platform !== 'win32') {
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
