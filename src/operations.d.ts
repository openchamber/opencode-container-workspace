import type { WorkspaceProviderOperations } from './contracts.js';

export interface WorkspaceOperationsOptions {
  policy?: unknown;
  sourceDirectory?: string;
}

export function createWorkspaceProviderOperations(options?: WorkspaceOperationsOptions): WorkspaceProviderOperations;
