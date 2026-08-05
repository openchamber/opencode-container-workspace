import { CleanupError } from './errors.js';
import { randomUUID } from 'node:crypto';
import { deleteWorkspaceState, readWorkspaceState, withWorkspaceLock, writeWorkspaceState } from './state-store.js';

export async function createTransaction(identity, callback) {
  return withWorkspaceLock(identity.providerResourceID, async () => {
    const existing = await readWorkspaceState(identity.providerResourceID);
    if (existing && existing.lifecycle !== 'creating') throw new Error(`Workspace operation state already exists and requires reconciliation: ${identity.providerResourceID} (${existing.lifecycle ?? 'unknown'})`);
    if (existing && ['provider', 'projectID', 'controlPlaneWorkspaceID'].some((key) => existing[key] !== identity[key])) throw new Error(`Interrupted workspace operation identity mismatch: ${identity.providerResourceID}`);
    const journal = existing ?? {
      version: 1,
      ...identity,
      lifecycle: 'creating',
      operationID: randomUUID(),
      createdAt: new Date().toISOString(),
      createdResources: [],
      resourceSteps: [],
    };
    journal.resourceSteps ??= (journal.createdResources ?? []).map((resource) => ({ resource, status: 'created' }));
    if (!existing) await writeWorkspaceState(identity.providerResourceID, journal);
    const rollbacks = [];
    const transaction = {
      recovering: Boolean(existing),
      async bindSnapshot(generation) {
        if (typeof generation !== 'string' || !generation) throw new TypeError('Workspace source snapshot generation is required');
        if (journal.baselineGeneration === undefined) {
          journal.baselineGeneration = generation;
          await writeWorkspaceState(identity.providerResourceID, journal);
          return;
        }
        if (journal.baselineGeneration !== generation) {
          const error = new Error('Workspace source changed after interrupted creation; cleanup or restore the original source before retrying');
          error.code = 'WORKSPACE_SOURCE_CHANGED_DURING_RECOVERY';
          throw error;
        }
      },
      async create(resource, create, rollback, verify) {
        let step = journal.resourceSteps.find((item) => item.resource === resource);
        if (!step) {
          step = { resource, status: 'pending', intendedAt: new Date().toISOString() };
          journal.resourceSteps.push(step);
          await writeWorkspaceState(identity.providerResourceID, journal);
        } else if (step.status === 'created') {
          if (typeof verify !== 'function') throw new Error(`Interrupted resource creation cannot be verified: ${resource}`);
          if (await verify()) {
            step.verifiedAt = new Date().toISOString();
            await writeWorkspaceState(identity.providerResourceID, journal);
            return;
          }
          step.status = 'pending';
          await writeWorkspaceState(identity.providerResourceID, journal);
        } else if (step.status === 'pending') {
          if (typeof verify !== 'function') throw new Error(`Interrupted resource creation cannot be verified: ${resource}`);
          if (await verify()) {
            markCreated(journal, step);
            step.verifiedAt = new Date().toISOString();
            await writeWorkspaceState(identity.providerResourceID, journal);
            return;
          }
        }
        try {
          await create();
        } catch (error) {
          if (typeof verify === 'function') {
            if (await verify()) {
              markCreated(journal, step);
              rollbacks.unshift({ resource, rollback, step });
            } else {
              step.status = 'absent';
            }
            await writeWorkspaceState(identity.providerResourceID, journal);
          }
          throw error;
        }
        markCreated(journal, step);
        rollbacks.unshift({ resource, rollback, step });
        await writeWorkspaceState(identity.providerResourceID, journal);
      },
      async update(patch) {
        Object.assign(journal, patch);
        await writeWorkspaceState(identity.providerResourceID, journal);
      },
    };
    try {
      const result = await callback(transaction, journal);
      journal.lifecycle = 'ready';
      journal.committedAt = new Date().toISOString();
      await writeWorkspaceState(identity.providerResourceID, journal);
      return result;
    } catch (cause) {
      if (cause?.code === 'WORKSPACE_SOURCE_CHANGED_DURING_RECOVERY') {
        journal.primaryError = safeMessage(cause);
        journal.updatedAt = new Date().toISOString();
        await writeWorkspaceState(identity.providerResourceID, journal);
        throw cause;
      }
      const rollbackFailures = [];
      for (const item of rollbacks) {
        try {
          await item.rollback();
          item.step.status = 'rolled-back';
          await writeWorkspaceState(identity.providerResourceID, journal);
        } catch (error) {
          rollbackFailures.push({ resource: item.resource, error });
        }
      }
      const remainingResources = journal.resourceSteps.filter((step) => step.status === 'pending' || step.status === 'created').map((step) => step.resource);
      if (rollbackFailures.length === 0 && remainingResources.length === 0) await deleteWorkspaceState(identity.providerResourceID);
      else {
        journal.lifecycle = 'failed';
        journal.primaryError = safeMessage(cause);
        journal.rollbackFailures = rollbackFailures.map(({ resource, error }) => ({ resource, message: safeMessage(error) }));
        journal.pendingResources = journal.resourceSteps.filter((step) => step.status === 'pending').map((step) => step.resource);
        journal.remainingResources = remainingResources;
        await writeWorkspaceState(identity.providerResourceID, journal);
      }
      if (rollbackFailures.length > 0) {
        throw new AggregateError([cause, ...rollbackFailures.map((item) => item.error)], `Workspace create failed and rollback was incomplete: ${safeMessage(cause)}`, { cause });
      }
      throw cause;
    }
  });
}

export async function cleanupTransaction(providerResourceID, cleanup) {
  return withWorkspaceLock(providerResourceID, async () => {
    const state = await readWorkspaceState(providerResourceID);
    const remainingResources = [];
    const retainedResources = [];
    const failures = [];
    let cleanupStarted = false;
    await writeWorkspaceState(providerResourceID, { ...(state ?? { version: 1, providerResourceID }), lifecycle: 'removing' });
    try {
      await cleanup({
        async remove(resource, action) {
          cleanupStarted = true;
          try {
            await action();
          } catch (error) {
            remainingResources.push(resource);
            failures.push(error);
          }
        },
        retain(resource) {
          cleanupStarted = true;
          retainedResources.push(resource);
        },
      });
    } catch (cause) {
      const unresolved = [...remainingResources, ...retainedResources, cleanupStarted ? 'provider-resources:cleanup-interrupted' : 'provider-resources:unverified'];
      await writeWorkspaceState(providerResourceID, {
        ...(state ?? { version: 1, providerResourceID }),
        lifecycle: 'degraded',
        remainingResources: [...new Set(unresolved)],
        retainedResources,
        cleanupError: safeMessage(cause),
        cleanupFailedAt: new Date().toISOString(),
      });
      throw cause;
    }
    if (failures.length > 0) {
      const remaining = [...remainingResources, ...retainedResources];
      await writeWorkspaceState(providerResourceID, { ...(state ?? { version: 1, providerResourceID }), lifecycle: 'degraded', remainingResources: remaining, retainedResources });
      throw new CleanupError('Workspace cleanup is incomplete', { remainingResources: remaining, failures, cause: failures[0] });
    }
    if (retainedResources.length > 0) {
      await writeWorkspaceState(providerResourceID, { ...(state ?? { version: 1, providerResourceID }), lifecycle: 'retained', remainingResources: retainedResources, retainedResources, retainedAt: new Date().toISOString() });
      // Retention is a policy-directed success, not a cleanup failure: every removable
      // resource is gone and the retained storage is recorded in workspace state.
      return { ok: true, remainingResources: [], retainedResources, diagnostics: ['Workspace storage was retained by policy'] };
    }
    await deleteWorkspaceState(providerResourceID);
    return { ok: true, remainingResources: [], diagnostics: [] };
  });
}

function markCreated(journal, step) {
  step.status = 'created';
  step.createdAt = new Date().toISOString();
  if (!journal.createdResources.includes(step.resource)) journal.createdResources.push(step.resource);
}

function safeMessage(error) {
  return error instanceof Error ? error.message : String(error);
}
