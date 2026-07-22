import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createWorkspaceSecrets, getWorkspaceToken, rotateWorkspaceCredentials, selectGrantedCredentials } from './auth.js';
import { readPolicy } from './policy.js';

describe('workspace credential delegation', () => {
  let root;
  beforeEach(async () => { root = await mkdtemp(join(tmpdir(), 'workspace-auth-test-')); process.env.OPENCHAMBER_WORKSPACE_STATE_DIR = root; });
  afterEach(async () => { delete process.env.OPENCHAMBER_WORKSPACE_STATE_DIR; await rm(root, { recursive: true, force: true }); });

  it('does not grant broad OpenCode authentication by default', () => {
    const policy = readPolicy();
    expect(selectGrantedCredentials(policy, { OPENCODE_AUTH_CONTENT: '{"secret":true}' })).toEqual({});
  });

  it('requires explicit policy and validates model auth before storing it', async () => {
    const policy = readPolicy({ credentials: { modelAuth: 'explicit-opencode-auth-content' } });
    const granted = selectGrantedCredentials(policy, { OPENCODE_AUTH_CONTENT: '{"provider":{"key":"secret"}}' });
    const secrets = await createWorkspaceSecrets('ws-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', granted);
    expect(secrets.modelAuthPath).toMatch(/model-auth\.json$/);
    expect(secrets.modelAuth).toBe('{"provider":{"key":"secret"}}');
    await expect(createWorkspaceSecrets('ws-ffffffffffffffffffffffffffffffff', { OPENCODE_AUTH_CONTENT: 'not-json' })).rejects.toThrow(/valid JSON/);
  });

  it('rotates endpoint credentials and revokes model authentication without returning secrets', async () => {
    const id = 'ws-11111111111111111111111111111111';
    const initial = await createWorkspaceSecrets(id, { OPENCODE_AUTH_CONTENT: '{"key":"old"}' });
    const providerUpdates = [];
    const result = await rotateWorkspaceCredentials(id, { modelAuth: null }, async (credentials) => providerUpdates.push(credentials));
    expect(result).toEqual({ rotatedEndpointToken: true, modelAuth: 'revoked' });
    expect(await getWorkspaceToken(initial.tokenRef)).not.toBe(initial.token);
    expect(providerUpdates).toHaveLength(1);
    expect(JSON.stringify(result)).not.toContain(providerUpdates[0].token);
  });

  it('reuses provisioned secrets when an interrupted create is retried', async () => {
    const id = 'ws-22222222222222222222222222222222';
    const initial = await createWorkspaceSecrets(id, { OPENCODE_AUTH_CONTENT: '{"key":"initial"}' });
    const retried = await createWorkspaceSecrets(id, { OPENCODE_AUTH_CONTENT: '{"key":"replacement"}' });
    expect(retried.token).toBe(initial.token);
    expect(retried.modelAuth).toBe('{"key":"initial"}');
    expect(await getWorkspaceToken(initial.tokenRef)).toBe(initial.token);
  });

  it('restores provider credentials when provider refresh fails after mutation', async () => {
    const id = 'ws-33333333333333333333333333333333';
    const initial = await createWorkspaceSecrets(id, { OPENCODE_AUTH_CONTENT: '{"key":"initial"}' });
    const updates = [];
    await expect(rotateWorkspaceCredentials(id, {}, async (credentials) => {
      updates.push(credentials);
      if (updates.length === 1) throw new Error('rollout failed after secret replacement');
    })).rejects.toThrow('rollout failed');
    expect(updates).toHaveLength(2);
    expect(updates[1]).toEqual({ token: initial.token, modelAuth: '{"key":"initial"}' });
    expect(await getWorkspaceToken(initial.tokenRef)).toBe(initial.token);
  });
});
