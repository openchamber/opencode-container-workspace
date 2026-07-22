import { PolicyError } from './errors.js';

export const WORKSPACE_PROVIDERS = Object.freeze(['docker', 'kubernetes', 'apple-container']);
export const METADATA_VERSION = 1;
export const RUNTIME_LAYOUT_VERSION = 1;

export function parseProviderKind(value) {
  if (!WORKSPACE_PROVIDERS.includes(value)) {
    throw new PolicyError(`Unsupported workspace provider: ${String(value)}`);
  }
  return value;
}

export function parseWorkspaceRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('Workspace record is required');
  if (!nonEmpty(value.id)) throw new TypeError('Workspace id is required');
  if (!nonEmpty(value.projectID)) throw new TypeError('Workspace projectID is required');
  return value;
}

export function parseWorkspaceMetadata(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('Workspace metadata is required');
  if (value.version !== METADATA_VERSION) throw new TypeError(`Unsupported workspace metadata version: ${String(value.version)}`);
  if (value.runtimeLayoutVersion !== RUNTIME_LAYOUT_VERSION) throw new TypeError(`Unsupported runtime layout version: ${String(value.runtimeLayoutVersion)}`);
  parseProviderKind(value.provider);
  for (const key of ['controlPlaneWorkspaceID', 'providerResourceID', 'projectID', 'createdAt', 'imageDigest', 'authRef', 'policyFingerprint']) {
    if (!nonEmpty(value[key])) throw new TypeError(`Workspace metadata ${key} is required`);
  }
  if (!value.resourceRefs || typeof value.resourceRefs !== 'object' || Array.isArray(value.resourceRefs)) {
    throw new TypeError('Workspace metadata resourceRefs is required');
  }
  return value;
}

export function parseWorkspaceExportArtifact(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || value.version !== 1) throw new TypeError('Workspace export artifact version 1 is required');
  for (const key of ['id', 'controlPlaneWorkspaceID', 'providerResourceID', 'projectID', 'provider', 'baselineGeneration', 'targetDirectory', 'createdAt', 'expiresAt', 'integrityHash']) if (!nonEmpty(value[key])) throw new TypeError(`Workspace export artifact ${key} is required`);
  parseProviderKind(value.provider);
  if (!Array.isArray(value.files) || !Array.isArray(value.blobs)) throw new TypeError('Workspace export artifact files and blobs are required');
  return value;
}

export { parseEgressPolicy } from './egress-gateway.js';
export { readPolicy as parseWorkspacePolicy } from './policy.js';

function nonEmpty(value) {
  return typeof value === 'string' && value.length > 0;
}
