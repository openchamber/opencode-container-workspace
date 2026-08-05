import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { cleanupTransaction, createTransaction } from './lifecycle.js';
import { readWorkspaceState, writeWorkspaceState } from './state-store.js';

describe('workspace create transaction', () => {
  let root;
  const identity = { provider: 'docker', providerResourceID: 'ws-dddddddddddddddddddddddddddddddd', projectID: 'project', controlPlaneWorkspaceID: 'control' };
  beforeEach(async () => { root = await mkdtemp(join(tmpdir(), 'workspace-lifecycle-test-')); process.env.OPENCHAMBER_WORKSPACE_STATE_DIR = root; });
  afterEach(async () => { delete process.env.OPENCHAMBER_WORKSPACE_STATE_DIR; await rm(root, { recursive: true, force: true }); });

  it('rolls back only successfully created resources in reverse order', async () => {
    const events = [];
    await expect(createTransaction(identity, async (transaction) => {
      await transaction.create('one', async () => events.push('create-one'), async () => events.push('remove-one'));
      await transaction.create('two', async () => events.push('create-two'), async () => events.push('remove-two'));
      await transaction.create('foreign', async () => { throw new Error('collision'); }, async () => events.push('remove-foreign'), async () => false);
    })).rejects.toThrow('collision');
    expect(events).toEqual(['create-one', 'create-two', 'remove-two', 'remove-one']);
    expect(await readWorkspaceState(identity.providerResourceID)).toBeNull();
  });

  it('preserves primary and rollback failures in durable state', async () => {
    const error = await createTransaction(identity, async (transaction) => {
      await transaction.create('one', async () => undefined, async () => { throw new Error('cleanup failed'); });
      throw new Error('create failed');
    }).catch((value) => value);
    expect(error).toBeInstanceOf(AggregateError);
    expect(error.message).toContain('create failed');
    expect(await readWorkspaceState(identity.providerResourceID)).toMatchObject({ lifecycle: 'failed', primaryError: 'create failed', rollbackFailures: [{ resource: 'one', message: 'cleanup failed' }] });
  });

  it('does not overwrite interrupted operation journals on retry', async () => {
    await expect(createTransaction(identity, async () => { throw new Error('interrupted'); })).rejects.toThrow('interrupted');
    // A clean rollback removes state, so create a durable failed journal through rollback failure.
    await createTransaction(identity, async (transaction) => {
      await transaction.create('one', async () => undefined, async () => { throw new Error('still present'); });
      throw new Error('failed');
    }).catch(() => undefined);
    await expect(createTransaction(identity, async () => undefined)).rejects.toThrow(/requires reconciliation/);
  });

  it('journals pending intent before creation and rolls back an ambiguously created resource', async () => {
    const events = [];
    await expect(createTransaction(identity, async (transaction) => {
      await transaction.create('one', async () => {
        expect(await readWorkspaceState(identity.providerResourceID)).toMatchObject({ resourceSteps: [{ resource: 'one', status: 'pending' }] });
        events.push('create');
        throw new Error('provider timed out');
      }, async () => events.push('rollback'), async () => true);
    })).rejects.toThrow('provider timed out');
    expect(events).toEqual(['create', 'rollback']);
    expect(await readWorkspaceState(identity.providerResourceID)).toBeNull();
  });

  it('resumes an interrupted creating journal after verifying the pending resource', async () => {
    await writeWorkspaceState(identity.providerResourceID, {
      version: 1, ...identity, lifecycle: 'creating', operationID: 'operation', createdResources: [],
      resourceSteps: [{ resource: 'one', status: 'pending' }],
    });
    const create = vi.fn();
    await createTransaction(identity, async (transaction) => {
      expect(transaction.recovering).toBe(true);
      await transaction.create('one', create, async () => undefined, async () => true);
    });
    expect(create).not.toHaveBeenCalled();
    expect(await readWorkspaceState(identity.providerResourceID)).toMatchObject({ lifecycle: 'ready', createdResources: ['one'], resourceSteps: [{ resource: 'one', status: 'created' }] });
  });

  it('binds recovery to the original source snapshot without deleting the journal', async () => {
    await writeWorkspaceState(identity.providerResourceID, {
      version: 1, ...identity, lifecycle: 'creating', operationID: 'operation', baselineGeneration: 'original',
      createdResources: ['volume:baseline'], resourceSteps: [{ resource: 'volume:baseline', status: 'created' }],
    });
    const callback = vi.fn(async (transaction) => transaction.bindSnapshot('changed'));
    await expect(createTransaction(identity, callback)).rejects.toMatchObject({ code: 'WORKSPACE_SOURCE_CHANGED_DURING_RECOVERY' });
    expect(await readWorkspaceState(identity.providerResourceID)).toMatchObject({
      lifecycle: 'creating', baselineGeneration: 'original', createdResources: ['volume:baseline'],
      primaryError: expect.stringContaining('source changed'),
    });
  });

  it('allows idempotent recovery with the exact original source snapshot', async () => {
    await writeWorkspaceState(identity.providerResourceID, {
      version: 1, ...identity, lifecycle: 'creating', operationID: 'operation', baselineGeneration: 'same',
      createdResources: [], resourceSteps: [],
    });
    await createTransaction(identity, async (transaction) => transaction.bindSnapshot('same'));
    expect(await readWorkspaceState(identity.providerResourceID)).toMatchObject({ lifecycle: 'ready', baselineGeneration: 'same' });
  });

  it('preserves an unverified pending resource instead of deleting it', async () => {
    await expect(createTransaction(identity, async (transaction) => {
      await transaction.create('one', async () => { throw new Error('ambiguous failure'); }, async () => undefined, async () => { throw new Error('provider unavailable'); });
    })).rejects.toThrow('provider unavailable');
    expect(await readWorkspaceState(identity.providerResourceID)).toMatchObject({ lifecycle: 'failed', pendingResources: ['one'] });
  });

  it('does not roll back resources verified from an interrupted process after a later failure', async () => {
    await writeWorkspaceState(identity.providerResourceID, {
      version: 1, ...identity, lifecycle: 'creating', operationID: 'operation', createdResources: ['existing'],
      resourceSteps: [{ resource: 'existing', status: 'created' }],
    });
    const removeExisting = vi.fn();
    await expect(createTransaction(identity, async (transaction) => {
      await transaction.create('existing', vi.fn(), removeExisting, async () => true);
      throw new Error('transient recovery failure');
    })).rejects.toThrow('transient recovery failure');
    expect(removeExisting).not.toHaveBeenCalled();
    expect(await readWorkspaceState(identity.providerResourceID)).toMatchObject({ lifecycle: 'failed', remainingResources: ['existing'] });
  });

  it('keeps a recoverable tombstone when cleanup retains storage', async () => {
    await writeWorkspaceState(identity.providerResourceID, { version: 1, ...identity, lifecycle: 'ready' });
    const result = await cleanupTransaction(identity.providerResourceID, async (cleanup) => {
      cleanup.retain('volume:mutable');
      cleanup.retain('volume:baseline');
    });
    expect(result).toMatchObject({ ok: true, remainingResources: [], retainedResources: ['volume:mutable', 'volume:baseline'], diagnostics: ['Workspace storage was retained by policy'] });
    expect(await readWorkspaceState(identity.providerResourceID)).toMatchObject({ lifecycle: 'retained', retainedResources: ['volume:mutable', 'volume:baseline'] });
  });

  it('records callback-level cleanup failure instead of leaving removing state', async () => {
    await writeWorkspaceState(identity.providerResourceID, { version: 1, ...identity, lifecycle: 'ready' });
    await expect(cleanupTransaction(identity.providerResourceID, async () => { throw new Error('ownership verification unavailable'); })).rejects.toThrow('ownership verification unavailable');
    expect(await readWorkspaceState(identity.providerResourceID)).toMatchObject({
      lifecycle: 'degraded',
      remainingResources: ['provider-resources:unverified'],
      cleanupError: 'ownership verification unavailable',
    });
  });
});
