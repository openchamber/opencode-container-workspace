import { describe, expect, it } from 'vitest';
import { readPolicy } from '../policy.js';
import { buildManifests, createKubernetesProvider, KUBERNETES_SEED_EXTRACT_COMMAND, kubernetesCredentialRefreshCommands } from './kubernetes.js';
import { canonicalResourceRefs, deriveWorkspaceIdentity } from '../metadata.js';

function policy() {
  return readPolicy({
    defaultImage: 'workspace-image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    egress: { mode: 'external', proxyUrl: 'http://10.0.0.10:3128', proxyCIDR: '10.0.0.10/32', dnsCIDRs: ['10.0.0.53/32'] },
    kubernetes: { allowedNamespaces: ['openchamber-workspaces'] },
  });
}

describe('Kubernetes provider manifests', () => {
  it('does not overwrite mounted PVC root metadata while extracting either source copy', () => {
    expect(KUBERNETES_SEED_EXTRACT_COMMAND.match(/tar --no-same-owner --no-overwrite-dir --strip-components=1/g)).toHaveLength(1);
    expect(KUBERNETES_SEED_EXTRACT_COMMAND).toContain('-C "$1"');
    expect(KUBERNETES_SEED_EXTRACT_COMMAND).toContain('$1/.openchamber-runtime/source-generation');
  });

  it('replaces the exact owned runtime pod before completing credential rotation', () => {
    const currentPolicy = policy();
    const info = createKubernetesProvider({ policy: currentPolicy, sourceDirectory: '/source' }).configure({ id: 'control-id', projectID: 'project-id' });
    const commands = kubernetesCredentialRefreshCommands(info.extra);
    expect(commands[0].args).toEqual([
      'delete', 'pod', '-l', `openchamber.io/resource-id=${info.extra.providerResourceID},openchamber.io/role=runtime`,
      '-n', currentPolicy.kubernetes.namespace, '--wait=true',
    ]);
    expect(commands[1].args).toContain(`deployment/${info.extra.resourceRefs.deployment}`);
  });

  it('creates separate baseline storage, ServiceAccount, enforced policy, probes, and provider secret files', () => {
    const currentPolicy = policy();
    const info = { id: 'control-id', projectID: 'project-id' };
    const identity = deriveWorkspaceIdentity(info, 'kubernetes');
    const refs = canonicalResourceRefs(identity.providerResourceID, 'kubernetes', currentPolicy);
    const manifests = buildManifests({ identity, refs, image: currentPolicy.defaultImage, policy: currentPolicy, token: 'endpoint-secret', modelAuth: '{"key":"model-secret"}', workspaceID: info.id });
    const kinds = manifests.infrastructure.map((item) => item.kind);
    expect(kinds).toEqual(expect.arrayContaining(['Secret', 'ServiceAccount', 'PersistentVolumeClaim', 'NetworkPolicy']));
    expect(manifests.infrastructure.filter((item) => item.kind === 'PersistentVolumeClaim')).toHaveLength(2);
    const networkPolicy = manifests.infrastructure.find((item) => item.kind === 'NetworkPolicy');
    expect(networkPolicy.spec.policyTypes).toEqual(['Ingress', 'Egress']);
    expect(networkPolicy.spec.ingress).toEqual([]);
    const podSpec = manifests.deployment.spec.template.spec;
    expect(podSpec.automountServiceAccountToken).toBe(false);
    expect(podSpec.securityContext.seccompProfile.type).toBe('RuntimeDefault');
    expect(podSpec.securityContext.fsGroupChangePolicy).toBe('OnRootMismatch');
    expect(manifests.seedPod.spec.securityContext.fsGroupChangePolicy).toBe('OnRootMismatch');
    expect(podSpec.containers[0].securityContext).toMatchObject({ allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: ['ALL'] } });
    expect(podSpec.containers[0]).toHaveProperty('startupProbe');
    expect(podSpec.containers[0]).toHaveProperty('readinessProbe');
    expect(podSpec.containers[0]).toHaveProperty('livenessProbe');
    expect(podSpec.containers[0].env).toContainEqual({ name: 'OPENCHAMBER_WORKSPACE_AUTH_TOKEN_FILE', value: '/var/run/openchamber-workspace/endpoint-token' });
    expect(podSpec.containers[0].startupProbe.exec.command.join(' ')).toContain('/var/run/openchamber-workspace/endpoint-token');
    expect(podSpec.containers[0].env.some((item) => item.name === 'OPENCODE_AUTH_CONTENT')).toBe(false);
    expect(JSON.stringify(manifests.deployment)).not.toContain('model-secret');
  });

  it('uses canonical metadata and requires complete ingress policy', () => {
    const currentPolicy = policy();
    const provider = createKubernetesProvider({ policy: currentPolicy, sourceDirectory: '/source' });
    const info = provider.configure({ id: 'control-id', projectID: 'project-id' });
    expect(info.extra.resourceRefs.baselinePVC).toMatch(/baseline$/);
    expect(() => readPolicy({ kubernetes: { connectivity: 'ingress' } })).toThrow(/complete ingress policy/);
    expect(() => readPolicy({ kubernetes: { networkPolicy: 'disabled' } })).toThrow(/cannot be disabled/);
  });

  it('builds HTTPS ingress and controller-scoped NetworkPolicy', () => {
    const currentPolicy = readPolicy({
      defaultImage: 'workspace-image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      egress: { mode: 'external', proxyUrl: 'http://10.0.0.10:3128', proxyCIDR: '10.0.0.10/32', dnsCIDRs: ['10.0.0.53/32'] },
      kubernetes: { connectivity: 'ingress', ingress: { ingressClassName: 'nginx', hostTemplate: '{resourceID}.workspaces.example.com', pathTemplate: '/', tls: { mode: 'existing-secret', secretName: 'workspace-tls' }, controllerNamespaceSelector: { 'kubernetes.io/metadata.name': 'ingress-nginx' }, controllerPodSelector: { 'app.kubernetes.io/name': 'ingress-nginx' }, annotations: { 'nginx.ingress.kubernetes.io/proxy-read-timeout': '3600' } } },
    });
    const info = { id: 'control-id', projectID: 'project-id' };
    const identity = deriveWorkspaceIdentity(info, 'kubernetes');
    const refs = canonicalResourceRefs(identity.providerResourceID, 'kubernetes', currentPolicy);
    const manifests = buildManifests({ identity, refs, image: currentPolicy.defaultImage, policy: currentPolicy, token: 'token', workspaceID: info.id });
    const ingress = manifests.infrastructure.find((item) => item.kind === 'Ingress');
    expect(ingress.spec.tls[0].hosts[0]).toBe(`${identity.providerResourceID}.workspaces.example.com`);
    expect(ingress.spec.rules[0].http.paths[0].backend.service.name).toBe(refs.service);
    const runtimePolicy = manifests.infrastructure.find((item) => item.kind === 'NetworkPolicy' && item.metadata.name === refs.networkPolicy);
    expect(runtimePolicy.spec.ingress[0].from[0]).toMatchObject({ namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'ingress-nginx' } }, podSelector: { matchLabels: { 'app.kubernetes.io/name': 'ingress-nginx' } } });
  });

  it('builds an isolated managed gateway and routes runtime proxy traffic only through it', () => {
    const currentPolicy = readPolicy({
      defaultImage: 'workspace-image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      egress: { mode: 'managed', gatewayImage: 'gateway@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', preset: 'custom', allowedDomains: ['api.example.com'], dnsCIDRs: ['10.0.0.53/32'] },
    });
    const info = { id: 'control-id', projectID: 'project-id' };
    const identity = deriveWorkspaceIdentity(info, 'kubernetes');
    const refs = canonicalResourceRefs(identity.providerResourceID, 'kubernetes', currentPolicy);
    const manifests = buildManifests({ identity, refs, image: currentPolicy.defaultImage, policy: currentPolicy, token: 'token', workspaceID: info.id });
    const gateway = manifests.infrastructure.find((item) => item.kind === 'Deployment' && item.metadata.name === refs.gatewayDeployment);
    expect(gateway.spec.template.spec.containers[0]).toMatchObject({ image: currentPolicy.egress.gatewayImage, securityContext: { readOnlyRootFilesystem: true, allowPrivilegeEscalation: false } });
    expect(gateway.spec.template.spec.containers[0].volumeMounts).toBeUndefined();
    const runtimeProxy = manifests.deployment.spec.template.spec.containers[0].env.find((item) => item.name === 'HTTPS_PROXY');
    expect(runtimeProxy.value).toBe(`http://${refs.gatewayService}:3128`);
    const gatewayPolicy = manifests.infrastructure.find((item) => item.kind === 'NetworkPolicy' && item.metadata.name === refs.gatewayNetworkPolicy);
    expect(gatewayPolicy.spec.podSelector.matchLabels['openchamber.io/role']).toBe('egress-gateway');
    expect(gatewayPolicy.spec.egress).toContainEqual(expect.objectContaining({
      to: [{ namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'kube-system' } }, podSelector: { matchLabels: { 'k8s-app': 'kube-dns' } } }],
    }));
  });
});
