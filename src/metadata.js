import { createHash } from 'node:crypto';
import { AUTH_HEADER, createTokenRef } from './auth.js';
import { METADATA_VERSION, RUNTIME_LAYOUT_VERSION, parseWorkspaceMetadata, parseWorkspaceRecord } from './contracts.js';

const WORKSPACE_DIR = '/workspace';
const BASELINE_DIR = '/baseline';
const OPENCODE_PORT = 4096;

export function deriveWorkspaceIdentity(info, provider) {
  parseWorkspaceRecord(info);
  const controlPlaneWorkspaceID = String(info.id);
  const projectID = String(info.projectID);
  const digest = createHash('sha256').update(`v1\0${provider}\0${projectID}\0${controlPlaneWorkspaceID}`).digest('hex').slice(0, 32);
  return { controlPlaneWorkspaceID, originalControlPlaneWorkspaceID: controlPlaneWorkspaceID, providerResourceID: `ws-${digest}`, projectID, provider };
}

export function workspaceName(providerResourceID, provider) {
  return `${provider}-${providerResourceID.slice(3, 15)}`;
}

export function resourceName(providerResourceID, suffix = '') {
  const value = `openchamber-${providerResourceID}${suffix ? `-${suffix}` : ''}`;
  return value.slice(0, 63).replace(/-+$/g, '');
}

export function createMetadata(info, provider, policy, resourceRefs, identity = deriveWorkspaceIdentity(info, provider)) {
  return Object.freeze({
    version: METADATA_VERSION,
    provider,
    controlPlaneWorkspaceID: identity.controlPlaneWorkspaceID,
    originalControlPlaneWorkspaceID: identity.originalControlPlaneWorkspaceID ?? identity.controlPlaneWorkspaceID,
    providerResourceID: identity.providerResourceID,
    projectID: identity.projectID,
    runtimeLayoutVersion: RUNTIME_LAYOUT_VERSION,
    createdAt: new Date().toISOString(),
    imageDigest: policy.defaultImage,
    resourceRefs: Object.freeze({ ...resourceRefs }),
    authRef: createTokenRef(identity.providerResourceID),
    policyFingerprint: fingerprintPolicy(policy),
  });
}

export function readMetadata(info, expectedProvider, policy) {
  const meta = parseWorkspaceMetadata(info?.extra);
  verifyMetadataIdentity(meta, info, expectedProvider);
  if (policy && meta.policyFingerprint !== fingerprintPolicy({ ...policy, defaultImage: meta.imageDigest })) {
    const error = new Error('Workspace policy fingerprint does not match the active policy');
    error.code = 'WORKSPACE_POLICY_MISMATCH';
    throw error;
  }
  verifyCanonicalResourceRefs(meta, canonicalResourceRefs(meta.providerResourceID, meta.provider, policy));
  return meta;
}

// Cleanup must stay possible after the active policy changes: ownership is proven by
// immutable identity, canonical naming, and provider labels, not by policy equality.
// A fingerprint mismatch is therefore reported as a diagnostic instead of a failure,
// and canonical naming is validated against the policy shape recorded at creation.
export function readCleanupMetadata(info, expectedProvider, policy) {
  const meta = parseWorkspaceMetadata(info?.extra);
  verifyMetadataIdentity(meta, info, expectedProvider);
  verifyCanonicalResourceRefs(meta, canonicalResourceRefs(meta.providerResourceID, meta.provider, cleanupPolicyShape(meta)));
  const diagnostics = [];
  if (policy && meta.policyFingerprint !== fingerprintPolicy({ ...policy, defaultImage: meta.imageDigest })) {
    diagnostics.push('Workspace was created under a different policy; cleanup used the resources recorded at creation');
  }
  return { meta, diagnostics };
}

function verifyMetadataIdentity(meta, info, expectedProvider) {
  if (expectedProvider && meta.provider !== expectedProvider) throw new Error(`Expected ${expectedProvider} workspace metadata, got ${meta.provider}`);
  if (info?.projectID && String(info.projectID) !== meta.projectID) throw new Error('Workspace project identity does not match metadata');
  if (meta.authRef !== createTokenRef(meta.providerResourceID)) throw new Error('Workspace authentication reference is not canonical');
}

function verifyCanonicalResourceRefs(meta, canonical) {
  for (const [key, value] of Object.entries(canonical)) {
    if (meta.resourceRefs[key] !== value) throw new Error(`Workspace metadata resource reference is not canonical: ${key}`);
  }
}

function cleanupPolicyShape(meta) {
  if (meta.provider !== 'kubernetes') return {};
  const refs = meta.resourceRefs ?? {};
  if (typeof refs.namespace !== 'string' || !refs.namespace) throw new Error('Workspace metadata namespace reference is missing');
  return {
    kubernetes: {
      namespace: refs.namespace,
      connectivity: refs.ingress ? 'ingress' : 'port-forward',
      ingress: { tls: { mode: refs.ingressTLSSecret ? 'cert-manager' : 'existing-secret' } },
    },
    egress: { mode: refs.gatewayDeployment ? 'managed' : 'external' },
  };
}

export function canonicalResourceRefs(providerResourceID, provider, policy) {
  const base = resourceName(providerResourceID);
  if (provider === 'docker') {
    return { runtime: base, access: `${base}-access`, gateway: `${base}-egress`, mutableVolume: `${base}-data`, baselineVolume: `${base}-baseline`, secretVolume: `${base}-secrets`, network: `${base}-network` };
  }
  if (provider === 'kubernetes') {
    const refs = {
      namespace: policy.kubernetes.namespace,
      deployment: base,
      service: base,
      secret: `${base}-secrets`,
      serviceAccount: base,
      mutablePVC: `${base}-data`,
      baselinePVC: `${base}-baseline`,
      networkPolicy: base,
      seedNetworkPolicy: `${base}-seed`,
    };
    if (policy.egress.mode === 'managed') {
      refs.gatewayDeployment = `${base}-egress`;
      refs.gatewayService = `${base}-egress`;
      refs.gatewayNetworkPolicy = `${base}-egress`;
    }
    if (policy.kubernetes.connectivity === 'ingress') {
      refs.ingress = base;
      if (policy.kubernetes.ingress.tls.mode === 'cert-manager') refs.ingressTLSSecret = `${base}-tls`;
    }
    return refs;
  }
  return { runtime: base, mutableVolume: `${base}-data`, baselineVolume: `${base}-baseline`, secretVolume: `${base}-secrets`, network: `${base}-network` };
}

export function providerLabels(identity, role, provider = identity.provider) {
  const originalWorkspaceID = identity.originalControlPlaneWorkspaceID ?? identity.controlPlaneWorkspaceID;
  if (provider === 'kubernetes') {
    return {
      'openchamber.io/managed': 'true',
      'openchamber.io/provider': provider,
      'openchamber.io/project-id': labelHash(identity.projectID),
      'openchamber.io/resource-id': identity.providerResourceID,
      'openchamber.io/role': role,
      'openchamber.io/original-workspace-id': labelHash(originalWorkspaceID),
    };
  }
  return {
    'openchamber.managed': 'true',
    'openchamber.workspace.provider': provider,
    'openchamber.project.id': labelHash(identity.projectID),
    'openchamber.resource.id': identity.providerResourceID,
    'openchamber.resource.role': role,
    'openchamber.workspace.original-id': labelHash(originalWorkspaceID),
  };
}

export function fingerprintPolicy(policy) {
  return createHash('sha256').update(stableStringify(policy)).digest('hex');
}

export function labelHash(value) {
  return `id-${createHash('sha256').update(String(value)).digest('hex').slice(0, 32)}`;
}

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

export const WORKSPACE_RUNTIME = { directory: WORKSPACE_DIR, baselineDirectory: BASELINE_DIR, port: OPENCODE_PORT };
export const AUTH_TARGET_HEADER = AUTH_HEADER;
