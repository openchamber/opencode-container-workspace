import { AUTH_HEADER, createTokenRef } from './auth.js';
import { sanitizeLabelValue } from './process.js';

const WORKSPACE_DIR = '/workspace';
const OPENCODE_PORT = 4096;

export function workspaceName(info, provider) {
  const suffix = sanitizeLabelValue(info.id).slice(-12);
  return `${provider}-${suffix}`;
}

function baseLabels(info, provider) {
  return {
    'openchamber.workspace.id': String(info.id),
    'openchamber.workspace.provider': provider,
    'openchamber.project.id': String(info.projectID ?? 'unknown'),
    'openchamber.managed': 'true',
  };
}

function kubernetesLabels(info, provider) {
  return {
    'openchamber.io/workspace-id': sanitizeLabelValue(info.id),
    'openchamber.io/provider': provider,
    'openchamber.io/project-id': sanitizeLabelValue(info.projectID ?? 'unknown'),
    'openchamber.io/managed': 'true',
  };
}

export function createExtra(info, provider, policy, runtime) {
  const image = policy.defaultImage;
  return {
    version: 1,
    provider,
    workspaceDir: WORKSPACE_DIR,
    opencodePort: OPENCODE_PORT,
    image,
    auth: {
      header: AUTH_HEADER,
      tokenRef: createTokenRef(info.id),
    },
    labels: provider === 'kubernetes' ? kubernetesLabels(info, provider) : baseLabels(info, provider),
    createdAt: Date.now(),
    storage: runtime.storage,
    runtime: runtime.runtime,
    policy: summarizePolicy(policy),
  };
}

export function readExtra(info, expectedProvider) {
  const extra = info?.extra;
  if (!extra || typeof extra !== 'object' || Array.isArray(extra)) {
    throw new Error(`Workspace ${info?.id ?? '<unknown>'} is missing metadata`);
  }
  if (extra.version !== 1) throw new Error(`Unsupported workspace metadata version: ${extra.version}`);
  if (expectedProvider && extra.provider !== expectedProvider) {
    throw new Error(`Expected ${expectedProvider} workspace metadata, got ${extra.provider}`);
  }
  if (extra.workspaceDir !== WORKSPACE_DIR || extra.opencodePort !== OPENCODE_PORT) {
    throw new Error('Workspace metadata does not match the supported runtime layout');
  }
  return extra;
}

function summarizePolicy(policy) {
  return {
    requirePinnedImage: policy.requirePinnedImage,
    allowedImages: policy.allowedImages,
    docker: policy.docker,
    kubernetes: policy.kubernetes,
    retention: policy.retention,
    secrets: { mode: policy.secrets.mode },
  };
}

export const WORKSPACE_RUNTIME = { directory: WORKSPACE_DIR, port: OPENCODE_PORT };
