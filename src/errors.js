class WorkspacePluginError extends Error {
  constructor(message, options = {}) {
    super(message);
    this.name = 'WorkspacePluginError';
    this.code = options.code ?? 'WORKSPACE_PLUGIN_ERROR';
    this.provider = options.provider;
    this.cause = options.cause;
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
