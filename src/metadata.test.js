import { describe, expect, it } from 'vitest';
import { canonicalResourceRefs, createMetadata, deriveWorkspaceIdentity, providerLabels, readCleanupMetadata, readMetadata } from './metadata.js';
import { readPolicy } from './policy.js';

describe('workspace metadata and ownership identity', () => {
  const policy = readPolicy({ defaultImage: 'image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' });
  const info = { id: 'control-id', projectID: 'project-id' };

  it('separates control-plane and immutable provider resource identity', () => {
    const identity = deriveWorkspaceIdentity(info, 'docker');
    expect(identity.controlPlaneWorkspaceID).toBe('control-id');
    expect(identity.providerResourceID).not.toContain('control-id');
    const metadata = createMetadata(info, 'docker', policy, canonicalResourceRefs(identity.providerResourceID, 'docker', policy), identity);
    expect(metadata.originalControlPlaneWorkspaceID).toBe('control-id');
    expect(readMetadata({ ...info, extra: metadata }, 'docker', policy)).toEqual(metadata);
  });

  it('binds labels to provider resource, project, provider, managed marker, and role', () => {
    const identity = deriveWorkspaceIdentity(info, 'docker');
    expect(providerLabels(identity, 'runtime')).toMatchObject({ 'openchamber.managed': 'true', 'openchamber.workspace.provider': 'docker', 'openchamber.resource.id': identity.providerResourceID, 'openchamber.resource.role': 'runtime' });
  });

  it('preserves the original workspace ID in audit labels after control-plane recovery', () => {
    const identity = { ...deriveWorkspaceIdentity(info, 'docker'), controlPlaneWorkspaceID: 'recovered-id' };
    expect(providerLabels(identity, 'runtime')['openchamber.workspace.original-id']).toBe(providerLabels(deriveWorkspaceIdentity(info, 'docker'), 'runtime')['openchamber.workspace.original-id']);
  });

  it('rejects use-path reads under a changed policy with a structured code', () => {
    const identity = deriveWorkspaceIdentity(info, 'docker');
    const metadata = createMetadata(info, 'docker', policy, canonicalResourceRefs(identity.providerResourceID, 'docker', policy), identity);
    const changed = { ...policy, credentials: { modelAuth: 'explicit-opencode-auth-content' } };
    let thrown;
    try {
      readMetadata({ ...info, extra: metadata }, 'docker', changed);
    } catch (error) {
      thrown = error;
    }
    expect(thrown?.message).toBe('Workspace policy fingerprint does not match the active policy');
    expect(thrown?.code).toBe('WORKSPACE_POLICY_MISMATCH');
  });

  it('keeps cleanup reads working after a policy change and reports a diagnostic', () => {
    const identity = deriveWorkspaceIdentity(info, 'docker');
    const metadata = createMetadata(info, 'docker', policy, canonicalResourceRefs(identity.providerResourceID, 'docker', policy), identity);
    const changed = { ...policy, credentials: { modelAuth: 'explicit-opencode-auth-content' } };
    const { meta, diagnostics } = readCleanupMetadata({ ...info, extra: metadata }, 'docker', changed);
    expect(meta).toEqual(metadata);
    expect(diagnostics).toEqual(['Workspace was created under a different policy; cleanup used the resources recorded at creation']);
  });

  it('returns no cleanup diagnostics when the policy still matches', () => {
    const identity = deriveWorkspaceIdentity(info, 'docker');
    const metadata = createMetadata(info, 'docker', policy, canonicalResourceRefs(identity.providerResourceID, 'docker', policy), identity);
    expect(readCleanupMetadata({ ...info, extra: metadata }, 'docker', policy).diagnostics).toEqual([]);
  });

  it('still rejects non-canonical resource references on the cleanup path', () => {
    const identity = deriveWorkspaceIdentity(info, 'docker');
    const metadata = createMetadata(info, 'docker', policy, canonicalResourceRefs(identity.providerResourceID, 'docker', policy), identity);
    const tampered = { ...metadata, resourceRefs: { ...metadata.resourceRefs, runtime: 'someone-elses-container' } };
    expect(() => readCleanupMetadata({ ...info, extra: tampered }, 'docker', policy)).toThrow(/not canonical: runtime/);
  });

  it('validates kubernetes cleanup references against the creation-time policy shape', () => {
    const k8sPolicy = readPolicy({ defaultImage: policy.defaultImage, kubernetes: { namespace: 'ns-created' } });
    const identity = deriveWorkspaceIdentity(info, 'kubernetes');
    const metadata = createMetadata(info, 'kubernetes', k8sPolicy, canonicalResourceRefs(identity.providerResourceID, 'kubernetes', k8sPolicy), identity);
    const movedNamespace = readPolicy({ defaultImage: policy.defaultImage, kubernetes: { namespace: 'ns-changed' } });
    expect(() => readMetadata({ ...info, extra: metadata }, 'kubernetes', movedNamespace)).toThrow();
    const { meta, diagnostics } = readCleanupMetadata({ ...info, extra: metadata }, 'kubernetes', movedNamespace);
    expect(meta.resourceRefs.namespace).toBe('ns-created');
    expect(diagnostics).toHaveLength(1);
  });
});
