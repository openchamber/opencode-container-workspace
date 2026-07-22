import { describe, expect, it } from 'vitest';
import { canonicalResourceRefs, createMetadata, deriveWorkspaceIdentity, providerLabels, readMetadata } from './metadata.js';
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
});
