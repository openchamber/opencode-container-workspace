export class WorkspacePluginError extends Error {
  constructor(message, options = {}) {
    super(message);
    this.name = 'WorkspacePluginError';
    this.code = options.code ?? 'WORKSPACE_PLUGIN_ERROR';
    this.provider = options.provider;
    this.cause = options.cause;
  }
}

export class StateStoreError extends WorkspacePluginError {
  constructor(message, options = {}) {
    super(message, { ...options, code: options.code ?? 'WORKSPACE_STATE_ERROR' });
    this.name = 'StateStoreError';
  }
}

export class OwnershipError extends WorkspacePluginError {
  constructor(message, options = {}) {
    super(message, { ...options, code: options.code ?? 'WORKSPACE_OWNERSHIP_ERROR' });
    this.name = 'OwnershipError';
  }
}

export class CleanupError extends WorkspacePluginError {
  constructor(message, options = {}) {
    super(message, { ...options, code: options.code ?? 'WORKSPACE_CLEANUP_INCOMPLETE' });
    this.name = 'CleanupError';
    this.remainingResources = options.remainingResources ?? [];
    this.failures = options.failures ?? [];
  }
}

export class ProcessError extends WorkspacePluginError {
  constructor(message, options = {}) {
    super(message, { ...options, code: options.code ?? 'WORKSPACE_PROCESS_ERROR' });
    this.name = 'ProcessError';
    this.kind = options.kind ?? 'exit';
    this.exitCode = options.exitCode ?? null;
    this.signal = options.signal ?? null;
    this.stdout = options.stdout ?? '';
    this.stderr = options.stderr ?? '';
    this.truncated = options.truncated ?? false;
  }
}

export class PolicyError extends WorkspacePluginError {
  constructor(message, options = {}) {
    super(message, { ...options, code: options.code ?? 'WORKSPACE_POLICY_ERROR' });
    this.name = 'PolicyError';
  }
}

export class ProviderUnavailableError extends WorkspacePluginError {
  constructor(message, options = {}) {
    super(message, { ...options, code: options.code ?? 'WORKSPACE_PROVIDER_UNAVAILABLE' });
    this.name = 'ProviderUnavailableError';
  }
}

export class HealthCheckError extends WorkspacePluginError {
  constructor(message, options = {}) {
    super(message, { ...options, code: options.code ?? 'WORKSPACE_HEALTH_CHECK_FAILED' });
    this.name = 'HealthCheckError';
  }
}
