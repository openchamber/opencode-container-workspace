import { parseProviderKind, parseWorkspaceMetadata, parseWorkspaceRecord } from './contracts.js';
import { readPolicy } from './policy.js';
import { createDockerProvider } from './providers/docker.js';
import { createKubernetesProvider } from './providers/kubernetes.js';
import { createAppleContainerProvider } from './providers/apple-container.js';
import { finalizeArtifact } from './artifact.js';
import { realpathSync } from 'node:fs';
import { readWorkspaceState, withWorkspaceLock, writeWorkspaceState } from './state-store.js';

export function createWorkspaceProviderOperations(options = {}) {
  if (typeof window !== 'undefined') throw new Error('Workspace provider operations are server-side only');
  const policy = readPolicy(options.policy ?? options);
  const sourceDirectory = realpathSync(options.sourceDirectory ?? process.cwd());
  const providers = new Map([
    createDockerProvider({ policy, sourceDirectory }),
    createKubernetesProvider({ policy, sourceDirectory }),
    createAppleContainerProvider({ policy, sourceDirectory }),
  ].map((provider) => [provider.kind, provider]));

  function providerForWorkspace(workspace) {
    parseWorkspaceRecord(workspace);
    const kind = parseProviderKind(workspace.type);
    const metadata = parseWorkspaceMetadata(workspace.extra);
    if (metadata.provider !== kind) throw new Error('Workspace adapter type does not match provider metadata');
    return providers.get(kind);
  }

  async function adoptWorkspace(workspace) {
    parseWorkspaceRecord(workspace);
    const provider = providerForWorkspace(workspace);
    const metadata = parseWorkspaceMetadata(workspace.extra);
    if (metadata.projectID !== workspace.projectID) throw new Error('Workspace project identity does not match recovery metadata');
    if (metadata.controlPlaneWorkspaceID === workspace.id) return workspace;
    const originalControlPlaneWorkspaceID = metadata.originalControlPlaneWorkspaceID ?? metadata.controlPlaneWorkspaceID;
    return withWorkspaceLock(metadata.providerResourceID, async () => {
      const state = await readWorkspaceState(metadata.providerResourceID);
      if (!state || state.providerResourceID !== metadata.providerResourceID || state.provider !== metadata.provider || state.projectID !== metadata.projectID) {
        throw new Error('Workspace recovery state identity mismatch');
      }
      const alreadyAdopted = state.controlPlaneWorkspaceID === workspace.id
        && (state.originalControlPlaneWorkspaceID ?? originalControlPlaneWorkspaceID) === originalControlPlaneWorkspaceID;
      if (!alreadyAdopted && state.controlPlaneWorkspaceID !== metadata.controlPlaneWorkspaceID) {
        throw new Error('Workspace recovery control-plane identity mismatch');
      }
      const recovered = {
        ...workspace,
        extra: Object.freeze({ ...metadata, controlPlaneWorkspaceID: workspace.id, originalControlPlaneWorkspaceID }),
      };
      const verification = await provider.reconcile(alreadyAdopted ? recovered : workspace);
      if (!verification || verification.status !== 'ready') {
        const error = new Error('Workspace recovery ownership verification failed');
        error.diagnostics = Array.isArray(verification?.diagnostics) ? verification.diagnostics : [];
        throw error;
      }
      if (!alreadyAdopted) {
        const verifiedState = await readWorkspaceState(metadata.providerResourceID);
        if (!verifiedState || verifiedState.controlPlaneWorkspaceID !== metadata.controlPlaneWorkspaceID || verifiedState.provider !== metadata.provider || verifiedState.projectID !== metadata.projectID) {
          throw new Error('Workspace recovery state changed during ownership verification');
        }
        await writeWorkspaceState(metadata.providerResourceID, {
          ...verifiedState,
          controlPlaneWorkspaceID: workspace.id,
          originalControlPlaneWorkspaceID,
          adoptedAt: new Date().toISOString(),
        });
      }
      return recovered;
    });
  }

  // Cleanup-safe adoption: verifies immutable identity against persisted state but does
  // not require a healthy reconcile. A degraded or policy-mismatched workspace must stay
  // deletable; per-resource ownership labels are verified inside provider remove().
  async function adoptWorkspaceForCleanup(workspace) {
    parseWorkspaceRecord(workspace);
    providerForWorkspace(workspace);
    const metadata = parseWorkspaceMetadata(workspace.extra);
    if (metadata.projectID !== workspace.projectID) throw new Error('Workspace project identity does not match recovery metadata');
    if (metadata.controlPlaneWorkspaceID === workspace.id) return workspace;
    const originalControlPlaneWorkspaceID = metadata.originalControlPlaneWorkspaceID ?? metadata.controlPlaneWorkspaceID;
    const state = await readWorkspaceState(metadata.providerResourceID);
    if (!state || state.providerResourceID !== metadata.providerResourceID || state.provider !== metadata.provider || state.projectID !== metadata.projectID) {
      throw new Error('Workspace recovery state identity mismatch');
    }
    if (state.controlPlaneWorkspaceID !== workspace.id && state.controlPlaneWorkspaceID !== metadata.controlPlaneWorkspaceID) {
      throw new Error('Workspace recovery control-plane identity mismatch');
    }
    return { ...workspace, extra: Object.freeze({ ...metadata, controlPlaneWorkspaceID: workspace.id, originalControlPlaneWorkspaceID }) };
  }

  return Object.freeze({
    async validateProvider(kind) {
      return providers.get(parseProviderKind(kind)).validate();
    },
    /** Completes one setup requirement for a provider that can do so itself. */
    async prepareProvider(kind, action) {
      const target = providers.get(parseProviderKind(kind));
      if (typeof target.setup !== 'function') throw new Error(`Provider ${kind} has no setup actions`);
      if (typeof action !== 'string' || !action) throw new TypeError('action is required');
      return target.setup(action);
    },
    async discoverProject(projectID) {
      if (typeof projectID !== 'string' || !projectID) throw new TypeError('projectID is required');
      const workspaces = [];
      const failures = [];
      const completeProviders = [];
      for (const provider of providers.values()) {
        try {
          workspaces.push(...await provider.list({ instance: { project: { id: projectID } } }));
          completeProviders.push(provider.kind);
        } catch (error) {
          failures.push({ provider: provider.kind, message: error instanceof Error ? error.message : String(error), code: error?.code });
        }
      }
      return { projectID, workspaces, failures, completeProviders };
    },
    async inspectWorkspace(workspace) {
      workspace = await adoptWorkspace(workspace);
      const provider = providerForWorkspace(workspace);
      const health = await provider.health(workspace);
      const metadata = parseWorkspaceMetadata(workspace.extra);
      return { provider: provider.kind, providerResourceID: metadata.providerResourceID, health, diagnostics: [] };
    },
    async cleanupWorkspace(workspace) {
      workspace = await adoptWorkspaceForCleanup(workspace);
      return providerForWorkspace(workspace).remove(workspace);
    },
    async reconcileWorkspace(workspace) {
      workspace = await adoptWorkspace(workspace);
      const metadata = parseWorkspaceMetadata(workspace.extra);
      return withWorkspaceLock(metadata.providerResourceID, () => providerForWorkspace(workspace).reconcile(workspace));
    },
    async rotateWorkspaceCredentials(workspace, request) {
      workspace = await adoptWorkspace(workspace);
      return providerForWorkspace(workspace).rotateCredentials(workspace, request);
    },
    async exportWorkspace(workspace, sink) {
      workspace = await adoptWorkspace(workspace);
      const metadata = parseWorkspaceMetadata(workspace.extra);
      return withWorkspaceLock(metadata.providerResourceID, async () => {
        const result = await providerForWorkspace(workspace).exportWorkspace(workspace);
        const artifact = finalizeArtifact(result, metadata, sourceDirectory);
        if (sink && typeof sink.write === 'function') {
          await new Promise((resolve, reject) => sink.write(JSON.stringify(artifact), (error) => error ? reject(error) : resolve()));
          return { id: artifact.id, integrityHash: artifact.integrityHash, streamed: true };
        }
        return artifact;
      });
    },
    adoptWorkspace,
  });
}
