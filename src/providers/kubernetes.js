import { spawn } from 'node:child_process';
import { createReadStream, existsSync } from 'node:fs';
import { createServer } from 'node:net';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { commandExists, run, runJson, spawnBackground } from '../process.js';
import { CleanupError, OwnershipError, ProviderUnavailableError } from '../errors.js';
import { canonicalResourceRefs, createMetadata, deriveWorkspaceIdentity, labelHash, providerLabels, readCleanupMetadata, readMetadata, workspaceName, WORKSPACE_RUNTIME } from '../metadata.js';
import { createWorkspaceSecrets, getWorkspaceToken, rotateWorkspaceCredentials, selectGrantedCredentials } from '../auth.js';
import { requireKubernetesEgress, validateGatewayImage, validateImage } from '../policy.js';
import { grantedEgressPolicy } from '../egress-domains.js';
import { parseAuthCanIList, permissionsNeedingProbe } from './rbac-listing.js';
import { waitForHttpHealth } from '../health.js';
import { KUBERNETES_TOKEN_FILE, KUBERNETES_TOKEN_MOUNT_PATH, PROVIDER_MODEL_AUTH_FILE, runtimeCommand, runtimeEnvironment } from '../runtime-command.js';
import { cleanupTransaction, createTransaction } from '../lifecycle.js';
import { readWorkspaceState, writeWorkspaceState } from '../state-store.js';
import { createSourceSnapshot, resolveSnapshotSource } from '../snapshot.js';
import { ARTIFACT_LIMITS, RUNTIME_ARTIFACT_SCRIPT } from '../artifact.js';
import { checkNetworkPolicyEnforcement, lastEnforcementVerdict, requireNetworkPolicyEnforcement } from './network-policy-enforcement.js';

const portForwards = new Map();
// Cluster DNS is a property of the cluster, so it is cached per kubeconfig context, and
// expires so a cluster that is rebuilt under the same context name is not answered from
// a stale entry for the lifetime of the process.
const DNS_CACHE_TTL_MS = 10 * 60 * 1000;
const dnsCIDRCache = new Map();

export function resetKubernetesDiscoveryCache() {
  dnsCIDRCache.clear();
}

export const KUBERNETES_SEED_EXTRACT_COMMAND = `set -eu; cat > /tmp/source.tar; tar --no-same-owner --no-overwrite-dir --strip-components=1 -xf /tmp/source.tar -C "$1"; mkdir -p "$1/.openchamber-runtime"; printf '%s' "$2" > "$1/.openchamber-runtime/source-generation"`;

export function createKubernetesProvider({ policy, sourceDirectory }) {
  const provider = 'kubernetes';
  const kubectl = (args, options = {}) => run('kubectl', [...contextArgs(policy), ...args], options);

  async function preflight() {
    // Environment first, policy second: "no cluster here" is both more fundamental and
    // more actionable than "the egress policy is incomplete", and reporting the policy
    // gap first hides the real reason this host cannot run Kubernetes workspaces.
    await kubectl(['version', '--client=true'], { timeoutMs: 15_000 }).catch((cause) => { throw new ProviderUnavailableError('kubectl is not available', { provider, code: 'WORKSPACE_PROVIDER_CLI_MISSING', cause }); });
    if (!kubernetesConfigured(policy)) throw new ProviderUnavailableError('No Kubernetes configuration was found for this host', { provider, code: 'WORKSPACE_PROVIDER_NOT_CONFIGURED' });
    await kubectl(['get', 'namespace', policy.kubernetes.namespace, '-o', 'name'], { timeoutMs: 20_000 }).catch((cause) => {
      const text = `${cause?.stderr ?? ''} ${cause instanceof Error ? cause.message : String(cause)}`;
      if (/NotFound|not found/i.test(text)) {
        throw new ProviderUnavailableError(`Kubernetes namespace does not exist: ${policy.kubernetes.namespace}`, { provider, code: 'WORKSPACE_PROVIDER_NAMESPACE_MISSING', cause });
      }
      throw new ProviderUnavailableError(`Kubernetes cluster is not reachable: ${cause instanceof Error ? cause.message : String(cause)}`, { provider, code: 'WORKSPACE_PROVIDER_CLUSTER_UNREACHABLE', cause });
    });
    // Every check is a process spawn, and two dozen of them cost seconds on Windows —
    // creating the processes, not the round trips, which is why raising the concurrency
    // did not help. One listing answers for all of them at the price of one, and whatever
    // it does not clearly settle is still asked about directly below. Every denial is
    // collected rather than only the first, so one message names everything to request.
    const listing = await kubectl(['auth', 'can-i', '--list', '-n', policy.kubernetes.namespace], { timeoutMs: 20_000 })
      .then((result) => parseAuthCanIList(result.stdout))
      .catch(() => []);
    const unsettled = permissionsNeedingProbe(listing, requiredPermissions(policy));
    const denied = await mapWithConcurrency(unsettled, RBAC_PROBE_CONCURRENCY, async ([verb, resource]) => {
      const { stdout } = await kubectl(['auth', 'can-i', verb, resource, '-n', policy.kubernetes.namespace], { timeoutMs: 20_000 });
      return stdout.trim() === 'yes' ? null : `${verb} ${resource}`;
    });
    const missing = denied.filter(Boolean);
    if (missing.length > 0) {
      throw new ProviderUnavailableError(
        `Kubernetes RBAC denies ${missing.join(', ')} in namespace ${policy.kubernetes.namespace}`,
        { provider, code: 'WORKSPACE_PROVIDER_RBAC_DENIED' },
      );
    }
    // Validated after the environment checks because the DNS address is discovered from
    // the cluster, and an unreachable cluster is a more actionable answer than a policy gap.
    requireKubernetesEgress(policy, await resolveDnsCIDRs());
    if (policy.kubernetes.connectivity === 'ingress') {
      await kubectl(['get', 'ingressclass', policy.kubernetes.ingress.ingressClassName, '-o', 'name'], { timeoutMs: 20_000 });
      if (policy.kubernetes.ingress.tls.mode === 'existing-secret') await kubectl(['get', 'secret', policy.kubernetes.ingress.tls.secretName, '-n', policy.kubernetes.namespace, '-o', 'name'], { timeoutMs: 20_000 });
      const namespaceSelector = selectorString(policy.kubernetes.ingress.controllerNamespaceSelector);
      const podSelector = selectorString(policy.kubernetes.ingress.controllerPodSelector);
      const namespaces = JSON.parse((await kubectl(['get', 'namespaces', '-l', namespaceSelector, '-o', 'json'], { timeoutMs: 30_000 })).stdout).items ?? [];
      if (namespaces.length === 0) throw new ProviderUnavailableError('Kubernetes ingress controller namespace selector matches no namespaces', { provider, code: 'WORKSPACE_PROVIDER_INGRESS_CONTROLLER_MISSING' });
      const namespaceNames = new Set(namespaces.map((item) => item.metadata?.name));
      const pods = JSON.parse((await kubectl(['get', 'pods', '--all-namespaces', '-l', podSelector, '-o', 'json'], { timeoutMs: 30_000 })).stdout).items ?? [];
      if (!pods.some((item) => namespaceNames.has(item.metadata?.namespace))) throw new ProviderUnavailableError('Kubernetes ingress controller selectors match no pods', { provider, code: 'WORKSPACE_PROVIDER_INGRESS_CONTROLLER_MISSING' });
    }
    // Carries forward what an earlier create proved about this namespace; the probe
    // itself is too slow to run on a readiness check.
    const enforcement = lastEnforcementVerdict(policy.kubernetes.context, policy.kubernetes.namespace);
    return { provider, available: true, diagnostics: enforcement?.diagnostics ?? [], isolation: enforcement ? { verdict: enforcement.verdict } : null };
  }

/**
   * The image the isolation probe runs. The probe only needs a runtime that can open a
   * TCP connection, so it uses the egress gateway image where managed egress already
   * requires it: a quarter the size of the workspace image, which matters because a
   * cluster seeing either for the first time must download it before answering.
   */
  function isolationProbeImage() {
    if (policy.egress.mode === 'managed' && policy.egress.gatewayImage) return validateGatewayImage(policy.egress.gatewayImage);
    return validateImage(policy, policy.defaultImage);
  }

  /**
   * The address of the cluster's DNS service, which is different on every cluster and is
   * therefore discovered rather than asked for. The setting remains an override, and is
   * the only route left when RBAC hides `kube-system` from this account.
   */
  async function resolveDnsCIDRs() {
    if (policy.egress.dnsCIDRs.length > 0) return policy.egress.dnsCIDRs;
    const cached = dnsCIDRCache.get(policy.kubernetes.context ?? '');
    if (cached && cached.expiresAt > Date.now()) return cached.cidrs;
    let discovered = [];
    try {
      const { stdout } = await kubectl(['get', 'service', '-n', 'kube-system', '-l', 'k8s-app=kube-dns', '-o', 'json'], { timeoutMs: 20_000 });
      const services = JSON.parse(stdout).items ?? [];
      const addresses = services.flatMap((item) => item?.spec?.clusterIPs ?? (item?.spec?.clusterIP ? [item.spec.clusterIP] : []));
      discovered = addresses.filter((address) => typeof address === 'string' && address && address !== 'None')
        .map((address) => (address.includes(':') ? `${address}/128` : `${address}/32`));
    } catch {
      discovered = [];
    }
    if (discovered.length === 0) {
      throw new ProviderUnavailableError(
        'The cluster DNS address could not be determined, and no DNS range is configured. Ask your cluster administrator for the DNS service address and set it under Advanced.',
        { provider, code: 'WORKSPACE_PROVIDER_DNS_UNRESOLVED' },
      );
    }
    dnsCIDRCache.set(policy.kubernetes.context ?? '', { cidrs: discovered, expiresAt: Date.now() + DNS_CACHE_TTL_MS });
    return discovered;
  }

  /**
   * What the host already knows about reaching a cluster. kubeconfig is where the
   * industry keeps this, and it binds cluster and namespace together, so it is read
   * rather than retyped. Only names travel: a kubeconfig also holds tokens, client
   * certificates and server addresses, and none of that belongs in a settings surface.
   */
  async function describe() {
    if (!kubernetesConfigured(policy)) return { provider, contexts: [], currentContext: null };
    try {
      const { stdout } = await run('kubectl', ['config', 'view', '-o', 'json'], { timeoutMs: 20_000 });
      const config = JSON.parse(stdout);
      const currentContext = typeof config['current-context'] === 'string' ? config['current-context'] : null;
      const contexts = (Array.isArray(config.contexts) ? config.contexts : [])
        .filter((entry) => typeof entry?.name === 'string' && entry.name)
        .map((entry) => ({
          name: entry.name,
          namespace: typeof entry.context?.namespace === 'string' ? entry.context.namespace : null,
          current: entry.name === currentContext,
        }));
      return { provider, contexts, currentContext };
    } catch {
      return { provider, contexts: [], currentContext: null };
    }
  }

  /**
   * Completes a setup requirement on the operator's behalf. Kept separate from preflight
   * so that inspecting readiness never changes the cluster.
   */
  async function setup(action) {
    if (action === 'create-namespace') {
      if (!kubernetesConfigured(policy)) throw new ProviderUnavailableError('No Kubernetes configuration was found for this host', { provider, code: 'WORKSPACE_PROVIDER_NOT_CONFIGURED' });
      const namespace = policy.kubernetes.namespace;
      const exists = await kubectl(['get', 'namespace', namespace, '-o', 'name'], { timeoutMs: 20_000 }).then(() => true).catch(() => false);
      if (!exists) await kubectl(['create', 'namespace', namespace], { timeoutMs: 30_000 });
      return { action, namespace, created: !exists };
    }
    if (action === 'check-isolation') {
      const result = await checkNetworkPolicyEnforcement(kubectl, { context: policy.kubernetes.context, namespace: policy.kubernetes.namespace, image: isolationProbeImage(), force: true });
      return { action, verdict: result.verdict, diagnostics: result.diagnostics, imageUnavailable: result.imageUnavailable === true };
    }
    throw new Error(`Unsupported Kubernetes setup action: ${action}`);
  }

  function configure(info) {
    const identity = deriveWorkspaceIdentity(info, provider);
    const image = validateImage(policy, policy.defaultImage);
    const refs = canonicalResourceRefs(identity.providerResourceID, provider, policy);
    return { ...info, name: workspaceName(identity.providerResourceID, provider), directory: WORKSPACE_RUNTIME.directory, extra: createMetadata(info, provider, { ...policy, defaultImage: image }, refs, identity) };
  }

  async function create(info, env = {}, _from, context) {
    await preflight();
    // Every isolation guarantee this provider makes rests on the cluster enforcing the
    // NetworkPolicies it writes, and acceptance of the objects proves nothing. Verified
    // here rather than in preflight so listing and readiness stay cheap.
    const enforcement = await requireNetworkPolicyEnforcement(kubectl, { provider, context: policy.kubernetes.context, namespace: policy.kubernetes.namespace, image: isolationProbeImage() });
    const meta = readMetadata(info, provider, policy);
    const identity = identityFromMetadata(meta);
    const refs = canonicalResourceRefs(meta.providerResourceID, provider, policy);
    const image = validateImage(policy, meta.imageDigest);
    const snapshotSource = resolveSnapshotSource(context, sourceDirectory);
    await createTransaction(identity, async (transaction) => {
      const sourceSnapshot = await createSourceSnapshot(snapshotSource);
      try {
      if (!transaction.recovering) await assertResourcesAbsent(kubectl, refs);
      await transaction.bindSnapshot(sourceSnapshot.generation);
      const grantedCredentials = selectGrantedCredentials(policy, env);
      const secrets = await createWorkspaceSecrets(meta.providerResourceID, grantedCredentials);
      const hostPort = await availableStablePort(meta.providerResourceID);
      await transaction.update({ hostPort, imageDigest: image });
      const manifests = buildManifests({ identity, refs, image, policy: { ...policy, egress: { ...grantedEgressPolicy(policy, grantedCredentials), dnsCIDRs: await resolveDnsCIDRs() } }, token: secrets.token, modelAuth: secrets.modelAuth });
      for (const manifest of manifests.infrastructure) {
        const resource = `${manifest.kind.toLowerCase()}:${manifest.metadata.name}`;
        await transaction.create(resource, () => createManifest(kubectl, manifest), async () => {
          await deleteResource(kubectl, manifest.kind, manifest.metadata.name, refs.namespace);
          if (manifest.kind === 'Ingress' && refs.ingressTLSSecret) await deleteCertManagerTLSSecret(kubectl, refs, policy);
        }, () => resourceExistsOwned(kubectl, manifest.kind, manifest.metadata.name, refs.namespace, manifest.metadata.labels));
      }
      if (refs.ingressTLSSecret) await transaction.create(`secret:${refs.ingressTLSSecret}`, () => waitForCertManagerTLSSecret(kubectl, refs, policy), () => deleteCertManagerTLSSecret(kubectl, refs, policy), () => certManagerTLSSecretExistsOwned(kubectl, refs, policy));
      if (policy.egress.mode === 'managed') await kubectl(['rollout', 'status', `deployment/${refs.gatewayDeployment}`, '-n', refs.namespace, '--timeout=120s'], { timeoutMs: 150_000 });
      const seed = manifests.seedPod;
      await transaction.create(`pod:${seed.metadata.name}`, () => createManifest(kubectl, seed), () => deleteResource(kubectl, 'pod', seed.metadata.name, refs.namespace), () => resourceExistsOwned(kubectl, 'pod', seed.metadata.name, refs.namespace, seed.metadata.labels));
      await kubectl(['wait', '--for=condition=Ready', `pod/${seed.metadata.name}`, '-n', refs.namespace, '--timeout=120s'], { timeoutMs: 150_000 });
      await transaction.create(
        `seed:${refs.mutablePVC}`,
        () => streamArchiveToSeedPod(sourceSnapshot.archivePath, refs, policy, WORKSPACE_RUNTIME.directory, sourceSnapshot.generation),
        async () => undefined,
        () => verifyKubernetesSeed(kubectl, seed.metadata.name, refs.namespace, WORKSPACE_RUNTIME.directory, sourceSnapshot.generation),
      );
      await transaction.create(
        `seed:${refs.baselinePVC}`,
        () => streamArchiveToSeedPod(sourceSnapshot.archivePath, refs, policy, WORKSPACE_RUNTIME.baselineDirectory, sourceSnapshot.generation),
        async () => undefined,
        () => verifyKubernetesSeed(kubectl, seed.metadata.name, refs.namespace, WORKSPACE_RUNTIME.baselineDirectory, sourceSnapshot.generation),
      );
      await deleteResource(kubectl, 'pod', seed.metadata.name, refs.namespace);
      await transaction.create(`deployment:${refs.deployment}`, () => createManifest(kubectl, manifests.deployment), () => deleteResource(kubectl, 'deployment', refs.deployment, refs.namespace), () => resourceExistsOwned(kubectl, 'deployment', refs.deployment, refs.namespace, manifests.deployment.metadata.labels));
      await kubectl(['rollout', 'status', `deployment/${refs.deployment}`, '-n', refs.namespace, '--timeout=120s'], { timeoutMs: 150_000 });
      await verifyKubernetesWorkspace(kubectl, meta, policy);
      await health(info);
      } finally {
        await sourceSnapshot.dispose();
      }
    });
  }

  async function target(info) {
    const meta = readMetadata(info, provider, policy);
    await verifyKubernetesWorkspace(kubectl, meta, policy);
    const state = await readOwnedState(meta);
    if (policy.kubernetes.connectivity === 'ingress') {
      const ingress = resolveIngressTarget(policy.kubernetes.ingress, meta.providerResourceID);
      return { type: 'remote', url: ingress.url, headers: { 'x-openchamber-workspace-token': await getWorkspaceToken(meta.authRef) } };
    }
    if (!state?.hostPort) throw new Error('Kubernetes workspace stable target port is missing');
    await ensurePortForward(meta, state.hostPort, policy);
    return { type: 'remote', url: `http://127.0.0.1:${state.hostPort}`, headers: { 'x-openchamber-workspace-token': await getWorkspaceToken(meta.authRef) } };
  }

  async function health(info) {
    const remote = await target(info);
    await waitForHttpHealth(remote.url, remote.headers, { timeoutMs: 90_000 });
    return { ok: true };
  }

  async function remove(info) {
    const { meta, diagnostics } = readCleanupMetadata(info, provider, policy);
    const refs = meta.resourceRefs;
    stopPortForward(meta.providerResourceID);
    const result = await cleanupTransaction(meta.providerResourceID, async (cleanup) => {
      await verifyExistingResources(kubectl, meta, policy, { requireIssuer: false });
      // The seed pod is deleted by a completed create, so it is not a canonical
      // resource and stays out of expectedResources — verification of a healthy
      // workspace must not demand it. But an interrupted create leaves it behind, and
      // while it exists the PVCs it mounts never finish terminating: their protection
      // finalizer waits on the pod, both PVC deletes below time out, and cleanup
      // reports incomplete forever. Removing it here, ownership-verified, is what
      // makes remove idempotent for that leftover.
      const seedPod = `${refs.deployment}-seed`;
      await cleanup.remove(`pod:${seedPod}`, async () => {
        if (await resourceExistsOwned(kubectl, 'pod', seedPod, refs.namespace, providerLabels(identityFromMetadata(meta), 'seed'))) {
          await deleteResource(kubectl, 'pod', seedPod, refs.namespace);
        }
      });
      for (const [kind, name] of expectedResources(refs).filter(([resourceKind]) => !['pvc'].includes(resourceKind))) {
        await cleanup.remove(`${kind}:${name}`, () => deleteResource(kubectl, kind, name, refs.namespace));
      }
      if (refs.ingressTLSSecret) await cleanup.remove(`secret:${refs.ingressTLSSecret}`, () => deleteCertManagerTLSSecret(kubectl, refs, policy, { requireIssuer: false }));
      if (!policy.retention.preserveOnDelete) {
        await cleanup.remove(`pvc:${refs.mutablePVC}`, () => deleteResource(kubectl, 'pvc', refs.mutablePVC, refs.namespace));
        await cleanup.remove(`pvc:${refs.baselinePVC}`, () => deleteResource(kubectl, 'pvc', refs.baselinePVC, refs.namespace));
      } else {
        cleanup.retain(`pvc:${refs.mutablePVC}`);
        cleanup.retain(`pvc:${refs.baselinePVC}`);
      }
      await assertResourcesAbsent(kubectl, refs);
    });
    return { ...result, diagnostics: [...diagnostics, ...(result.diagnostics ?? [])] };
  }

  async function list(context) {
    const projectID = context?.instance?.project?.id;
    if (!projectID) throw new Error('Kubernetes workspace discovery requires an authoritative project ID');
    // Discovery on hosts without any Kubernetes setup must stay silent: no kubectl or
    // no kubeconfig means there is nothing to discover, not a discovery failure.
    if (!commandExists('kubectl')) return [];
    if (!kubernetesConfigured(policy)) return [];
    const selector = `openchamber.io/managed=true,openchamber.io/provider=kubernetes,openchamber.io/role=runtime,openchamber.io/project-id=${labelHash(projectID)}`;
    const { stdout } = await kubectl(['get', 'deployment', '-n', policy.kubernetes.namespace, '-l', selector, '-o', 'json'], { timeoutMs: 30_000 });
    const result = [];
    for (const item of JSON.parse(stdout).items ?? []) {
      const providerResourceID = item.metadata?.labels?.['openchamber.io/resource-id'];
      if (!providerResourceID) continue;
      const state = await readWorkspaceState(providerResourceID);
      if (!state || state.projectID !== String(projectID) || state.provider !== provider) continue;
      const identity = { provider, providerResourceID, projectID: String(projectID), controlPlaneWorkspaceID: state.controlPlaneWorkspaceID, originalControlPlaneWorkspaceID: state.originalControlPlaneWorkspaceID ?? state.controlPlaneWorkspaceID };
      result.push({ type: provider, name: workspaceName(providerResourceID, provider), branch: null, directory: WORKSPACE_RUNTIME.directory, projectID: String(projectID), extra: createMetadata({ id: state.controlPlaneWorkspaceID, projectID: String(projectID) }, provider, policy, canonicalResourceRefs(providerResourceID, provider, policy), identity) });
    }
    return result;
  }

  async function exportWorkspace(info) {
    const meta = readMetadata(info, provider, policy);
    await verifyKubernetesWorkspace(kubectl, meta, policy);
    const state = await readOwnedState(meta);
    const snapshot = await runJson('kubectl', [...contextArgs(policy), 'exec', `deployment/${meta.resourceRefs.deployment}`, '-n', meta.resourceRefs.namespace, '--', 'node', '-e', RUNTIME_ARTIFACT_SCRIPT, WORKSPACE_RUNTIME.baselineDirectory, WORKSPACE_RUNTIME.directory, state.baselineGeneration, String(ARTIFACT_LIMITS.maxTextBytes), String(ARTIFACT_LIMITS.maxBlobBytes), String(ARTIFACT_LIMITS.maxTotalBytes)], { timeoutMs: 120_000, maxOutputBytes: ARTIFACT_LIMITS.maxOutputBytes, sensitiveOutput: true, sensitiveValues: [RUNTIME_ARTIFACT_SCRIPT] });
    return { ...snapshot, provider, providerResourceID: meta.providerResourceID };
  }

  async function reconcile(info) {
    const meta = readMetadata(info, provider, policy);
    try {
      await verifyKubernetesWorkspace(kubectl, meta, policy);
      const state = await readOwnedState(meta);
      const remote = await target(info);
      await waitForHttpHealth(remote.url, remote.headers, { timeoutMs: 15_000 });
      const repaired = policy.kubernetes.connectivity === 'port-forward' ? ['stable-port-forward'] : [];
      if (state.lifecycle !== 'ready') { await writeWorkspaceState(meta.providerResourceID, { ...state, lifecycle: 'ready', reconciledAt: new Date().toISOString() }); repaired.push('operation-journal'); }
      return { provider, providerResourceID: meta.providerResourceID, status: 'ready', diagnostics: [], repaired };
    } catch (error) {
      return { provider, providerResourceID: meta.providerResourceID, status: 'degraded', diagnostics: [{ code: error?.code ?? 'WORKSPACE_RECONCILE_FAILED', message: error instanceof Error ? error.message : String(error) }], repaired: [] };
    }
  }

  async function rotateCredentials(info, request = {}) {
    const meta = readMetadata(info, provider, policy);
    await verifyKubernetesWorkspace(kubectl, meta, policy);
    await readOwnedState(meta);
    if (request.modelAuth != null && policy.credentials.modelAuth !== 'explicit-opencode-auth-content') throw new Error('Model authentication grants are disabled by workspace policy');
    return rotateWorkspaceCredentials(meta.providerResourceID, request, async ({ token, modelAuth }) => {
      await verifyKubernetesWorkspace(kubectl, meta, policy);
      const stringData = { 'endpoint-token': token };
      if (modelAuth !== undefined) stringData['model-auth.json'] = modelAuth;
      const resourceVersion = (await kubectl(['get', 'secret', meta.resourceRefs.secret, '-n', meta.resourceRefs.namespace, '-o', 'jsonpath={.metadata.resourceVersion}'], { timeoutMs: 30_000 })).stdout;
      await kubectl(['replace', '-f', '-'], { input: JSON.stringify({ apiVersion: 'v1', kind: 'Secret', metadata: { name: meta.resourceRefs.secret, namespace: meta.resourceRefs.namespace, resourceVersion, labels: providerLabels(identityFromMetadata(meta), 'secrets') }, type: 'Opaque', stringData }), timeoutMs: 60_000, sensitiveOutput: true });
      stopPortForward(meta.providerResourceID);
      for (const { args, timeoutMs } of kubernetesCredentialRefreshCommands(meta)) await kubectl(args, { timeoutMs });
    });
  }

  return { kind: provider, configure, create, target, remove, list, health, exportWorkspace, reconcile, rotateCredentials, validate: preflight, setup, describe };
}

export function buildManifests({ identity, refs, image, policy, token, modelAuth }) {
  const namespace = refs.namespace;
  const secretData = { 'endpoint-token': token };
  if (modelAuth) secretData['model-auth.json'] = modelAuth;
  const runtimePolicy = policy.egress.mode === 'managed'
    ? { ...policy, egress: { ...policy.egress, proxyUrl: `http://${refs.gatewayService}:3128` } }
    : { ...policy, egress: { ...policy.egress, proxyUrl: policy.egress.proxyUrl } };
  const infrastructure = [
    resource('v1', 'Secret', refs.secret, namespace, providerLabels(identity, 'secrets'), { type: 'Opaque', stringData: secretData }),
    resource('v1', 'ServiceAccount', refs.serviceAccount, namespace, providerLabels(identity, 'service-account'), { automountServiceAccountToken: false }),
    pvc(refs.mutablePVC, 'mutable-storage'),
    pvc(refs.baselinePVC, 'baseline-storage'),
    resource('v1', 'Service', refs.service, namespace, providerLabels(identity, 'service'), { spec: { selector: selector(identity), ports: [{ port: WORKSPACE_RUNTIME.port, targetPort: WORKSPACE_RUNTIME.port }] } }),
    resource('networking.k8s.io/v1', 'NetworkPolicy', refs.networkPolicy, namespace, providerLabels(identity, 'network-policy'), { spec: { podSelector: { matchLabels: selector(identity) }, policyTypes: ['Ingress', 'Egress'], ingress: buildRuntimeIngress(policy), egress: buildRuntimeEgress(policy, identity, refs) } }),
    resource('networking.k8s.io/v1', 'NetworkPolicy', refs.seedNetworkPolicy, namespace, providerLabels(identity, 'seed-network-policy'), { spec: { podSelector: { matchLabels: roleSelector(identity, 'seed') }, policyTypes: ['Ingress', 'Egress'], ingress: [], egress: [] } }),
  ];
  if (policy.egress.mode === 'managed') {
    infrastructure.push(
      resource('v1', 'Service', refs.gatewayService, namespace, providerLabels(identity, 'egress-service'), { spec: { selector: roleSelector(identity, 'egress-gateway'), ports: [{ port: 3128, targetPort: 3128 }] } }),
      resource('apps/v1', 'Deployment', refs.gatewayDeployment, namespace, providerLabels(identity, 'egress-gateway'), { spec: { replicas: 1, selector: { matchLabels: roleSelector(identity, 'egress-gateway') }, template: { metadata: { labels: { ...providerLabels(identity, 'egress-gateway'), ...roleSelector(identity, 'egress-gateway') } }, spec: { serviceAccountName: refs.serviceAccount, automountServiceAccountToken: false, securityContext: { runAsNonRoot: true, runAsUser: 10001, runAsGroup: 10001, seccompProfile: { type: 'RuntimeDefault' } }, containers: [{ name: 'gateway', image: policy.egress.gatewayImage, env: [{ name: 'OPENCHAMBER_RESOURCE_ID', value: identity.providerResourceID }, { name: 'OPENCHAMBER_EGRESS_POLICY', value: JSON.stringify(policy.egress.gatewayPolicy) }], ports: [{ containerPort: 3128 }], securityContext: hardenedSecurity(), resources: { requests: { cpu: '50m', memory: '64Mi' }, limits: { cpu: '500m', memory: '256Mi' } }, readinessProbe: { tcpSocket: { port: 3128 }, periodSeconds: 5 }, livenessProbe: { tcpSocket: { port: 3128 }, periodSeconds: 10 } }] } } } }),
      resource('networking.k8s.io/v1', 'NetworkPolicy', refs.gatewayNetworkPolicy, namespace, providerLabels(identity, 'egress-network-policy'), { spec: { podSelector: { matchLabels: roleSelector(identity, 'egress-gateway') }, policyTypes: ['Ingress', 'Egress'], ingress: [{ from: [{ podSelector: { matchLabels: selector(identity) } }], ports: [{ protocol: 'TCP', port: 3128 }] }], egress: buildGatewayEgress(policy.egress) } }),
    );
  }
  if (policy.kubernetes.connectivity === 'ingress') infrastructure.push(buildIngress(identity, refs, policy.kubernetes.ingress));
  const seedPod = resource('v1', 'Pod', `${refs.deployment}-seed`, namespace, providerLabels(identity, 'seed'), {
    spec: {
      restartPolicy: 'Never', automountServiceAccountToken: false, serviceAccountName: refs.serviceAccount,
      securityContext: { runAsNonRoot: true, runAsUser: 1000, runAsGroup: 1000, fsGroup: 1000, fsGroupChangePolicy: 'OnRootMismatch', seccompProfile: { type: 'RuntimeDefault' } },
      containers: [{ name: 'seed', image, command: ['sh', '-lc', 'sleep 3600'], securityContext: hardenedSecurity(), resources: resources(policy), volumeMounts: [{ name: 'workspace', mountPath: WORKSPACE_RUNTIME.directory }, { name: 'baseline', mountPath: WORKSPACE_RUNTIME.baselineDirectory }, { name: 'tmp', mountPath: '/tmp' }] }],
      volumes: [{ name: 'workspace', persistentVolumeClaim: { claimName: refs.mutablePVC } }, { name: 'baseline', persistentVolumeClaim: { claimName: refs.baselinePVC } }, { name: 'tmp', emptyDir: { sizeLimit: '2Gi' } }],
    },
  });
  const probe = { exec: { command: ['node', '-e', `const fs=require('fs'),http=require('http');const t=fs.readFileSync('${KUBERNETES_TOKEN_FILE}','utf8');const r=http.get({host:'127.0.0.1',port:${WORKSPACE_RUNTIME.port},path:'/global/health',headers:{'x-openchamber-workspace-token':t}},x=>process.exit(x.statusCode===200?0:1));r.on('error',()=>process.exit(1));setTimeout(()=>process.exit(1),3000)`] }, timeoutSeconds: 5, periodSeconds: 10 };
  const runtimeEnv = [{ name: 'OPENCODE_EXPERIMENTAL_WORKSPACES', value: 'true' }, ...Object.entries(runtimeEnvironment({ policy: runtimePolicy }, KUBERNETES_TOKEN_FILE)).map(([name, value]) => ({ name, value }))];
  const deployment = resource('apps/v1', 'Deployment', refs.deployment, namespace, providerLabels(identity, 'runtime'), {
    spec: {
      replicas: 1, selector: { matchLabels: selector(identity) },
      template: { metadata: { labels: { ...providerLabels(identity, 'runtime'), ...selector(identity) } }, spec: {
        serviceAccountName: refs.serviceAccount, automountServiceAccountToken: false,
        securityContext: { runAsNonRoot: true, runAsUser: 1000, runAsGroup: 1000, fsGroup: 1000, fsGroupChangePolicy: 'OnRootMismatch', seccompProfile: { type: 'RuntimeDefault' } },
        containers: [{ name: 'opencode', image, workingDir: WORKSPACE_RUNTIME.directory, command: ['sh', '-lc', runtimeCommand(KUBERNETES_TOKEN_FILE, `${KUBERNETES_TOKEN_MOUNT_PATH}/model-auth.json`)], ports: [{ containerPort: WORKSPACE_RUNTIME.port }], env: runtimeEnv, resources: resources(policy), securityContext: hardenedSecurity(), startupProbe: { ...probe, failureThreshold: 30 }, readinessProbe: probe, livenessProbe: { ...probe, failureThreshold: 3 }, volumeMounts: [{ name: 'workspace', mountPath: WORKSPACE_RUNTIME.directory }, { name: 'baseline', mountPath: WORKSPACE_RUNTIME.baselineDirectory, readOnly: true }, { name: 'secrets', mountPath: KUBERNETES_TOKEN_MOUNT_PATH, readOnly: true }, { name: 'tmp', mountPath: '/tmp' }] }],
        volumes: [{ name: 'workspace', persistentVolumeClaim: { claimName: refs.mutablePVC } }, { name: 'baseline', persistentVolumeClaim: { claimName: refs.baselinePVC } }, { name: 'secrets', secret: { secretName: refs.secret, defaultMode: 0o440 } }, { name: 'tmp', emptyDir: { sizeLimit: '256Mi' } }],
      } },
    },
  });
  return { infrastructure, seedPod, deployment };

  function pvc(name, role) {
    return resource('v1', 'PersistentVolumeClaim', name, namespace, providerLabels(identity, role), { spec: { accessModes: ['ReadWriteOnce'], resources: { requests: { storage: policy.kubernetes.storage } } } });
  }
}

function resource(apiVersion, kind, name, namespace, labels, body) {
  return { apiVersion, kind, metadata: { name, namespace, labels }, ...body };
}

function selector(identity) {
  return roleSelector(identity, 'runtime');
}

function roleSelector(identity, role) {
  return { 'openchamber.io/resource-id': identity.providerResourceID, 'openchamber.io/role': role };
}

function hardenedSecurity() {
  return { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: ['ALL'] } };
}

function resources(policy) {
  return { requests: { cpu: policy.kubernetes.cpuRequest, memory: policy.kubernetes.memoryRequest }, limits: { cpu: policy.kubernetes.cpuLimit, memory: policy.kubernetes.memoryLimit } };
}

function buildRuntimeEgress(policy, identity) {
  const dns = dnsEgress(policy.egress.dnsCIDRs);
  if (policy.egress.mode === 'managed') return [...dns, { to: [{ podSelector: { matchLabels: roleSelector(identity, 'egress-gateway') } }], ports: [{ protocol: 'TCP', port: 3128 }] }];
  const proxy = new URL(policy.egress.proxyUrl);
  const port = Number(proxy.port || (proxy.protocol === 'http:' ? 80 : 443));
  return [...dns, { to: [{ ipBlock: { cidr: policy.egress.proxyCIDR } }], ports: [{ protocol: 'TCP', port }] }];
}

function buildGatewayEgress(egress) {
  const privateCIDRs = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '240.0.0.0/4'];
  const publicInternet = { to: [{ ipBlock: { cidr: '0.0.0.0/0', except: privateCIDRs } }, { ipBlock: { cidr: '::/0', except: ['::/128', '::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8'] } }] };
  const explicit = egress.gatewayPolicy.allowedCIDRs.map((cidr) => ({ to: [{ ipBlock: { cidr } }] }));
  return [...dnsEgress(egress.dnsCIDRs), publicInternet, ...explicit];
}

function dnsEgress(cidrs) {
  const ports = [{ protocol: 'UDP', port: 53 }, { protocol: 'TCP', port: 53 }];
  return [
    ...cidrs.map((cidr) => ({ to: [{ ipBlock: { cidr } }], ports })),
    { to: [{ namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'kube-system' } }, podSelector: { matchLabels: { 'k8s-app': 'kube-dns' } } }], ports },
  ];
}

function buildRuntimeIngress(policy) {
  if (policy.kubernetes.connectivity !== 'ingress') return [];
  return [{ from: [{ namespaceSelector: { matchLabels: policy.kubernetes.ingress.controllerNamespaceSelector }, podSelector: { matchLabels: policy.kubernetes.ingress.controllerPodSelector } }], ports: [{ protocol: 'TCP', port: WORKSPACE_RUNTIME.port }] }];
}

function buildIngress(identity, refs, ingressPolicy) {
  const target = resolveIngressTarget(ingressPolicy, identity.providerResourceID);
  const annotations = { ...ingressPolicy.annotations };
  if (ingressPolicy.tls.mode === 'cert-manager') annotations['cert-manager.io/cluster-issuer'] = ingressPolicy.tls.clusterIssuer;
  return resource('networking.k8s.io/v1', 'Ingress', refs.ingress, refs.namespace, providerLabels(identity, 'ingress'), { metadata: { name: refs.ingress, namespace: refs.namespace, labels: providerLabels(identity, 'ingress'), annotations }, spec: { ingressClassName: ingressPolicy.ingressClassName, tls: [{ hosts: [target.host], secretName: ingressPolicy.tls.mode === 'existing-secret' ? ingressPolicy.tls.secretName : refs.ingressTLSSecret }], rules: [{ host: target.host, http: { paths: [{ path: target.path, pathType: 'Prefix', backend: { service: { name: refs.service, port: { number: WORKSPACE_RUNTIME.port } } } }] } }] } });
}

export function resolveIngressTarget(policy, providerResourceID) {
  const host = policy.hostTemplate.replaceAll('{resourceID}', providerResourceID);
  const path = policy.pathTemplate.replaceAll('{resourceID}', providerResourceID);
  return { host, path, url: `https://${host}${path}` };
}

export function kubernetesCredentialRefreshCommands(meta) {
  const runtimeSelector = selectorString(selector(identityFromMetadata(meta)));
  return [
    { args: ['delete', 'pod', '-l', runtimeSelector, '-n', meta.resourceRefs.namespace, '--wait=true'], timeoutMs: 90_000 },
    { args: ['rollout', 'status', `deployment/${meta.resourceRefs.deployment}`, '-n', meta.resourceRefs.namespace, '--timeout=120s'], timeoutMs: 150_000 },
  ];
}

async function createManifest(kubectl, manifest) {
  await kubectl(['create', '-f', '-'], { timeoutMs: 60_000, input: JSON.stringify(manifest) });
}

async function deleteResource(kubectl, kind, name, namespace) {
  await kubectl(['delete', kind.toLowerCase(), name, '-n', namespace, '--ignore-not-found=true', '--wait=true'], { timeoutMs: 90_000 });
}

async function assertResourcesAbsent(kubectl, refs) {
  for (const [kind, name] of expectedResources(refs)) {
    const exists = await kubectl(['get', kind, name, '-n', refs.namespace, '-o', 'name'], { timeoutMs: 20_000 }).then(() => true).catch((error) => { if (isNotFound(error)) return false; throw error; });
    if (exists) throw new OwnershipError(`Kubernetes resource collision: ${kind}/${name}`);
  }
  if (refs.ingressTLSSecret && await certManagerTLSSecretExists(kubectl, refs)) throw new OwnershipError(`Kubernetes resource collision: secret/${refs.ingressTLSSecret}`);
}

async function verifyKubernetesWorkspace(kubectl, meta, policy) {
  const identity = identityFromMetadata(meta);
  for (const [kind, name, role] of expectedResources(meta.resourceRefs)) await verifyResource(kubectl, kind, name, meta.resourceRefs.namespace, providerLabels(identity, role));
  if (meta.resourceRefs.ingressTLSSecret) await verifyCertManagerTLSSecret(kubectl, meta.resourceRefs, policy);
}

async function verifyExistingResources(kubectl, meta, policy, { requireIssuer = true } = {}) {
  const identity = identityFromMetadata(meta);
  for (const [kind, name, role] of expectedResources(meta.resourceRefs)) await verifyResource(kubectl, kind, name, meta.resourceRefs.namespace, providerLabels(identity, role)).catch((error) => { if (!isNotFound(error)) throw error; });
  if (meta.resourceRefs.ingressTLSSecret) await verifyCertManagerTLSSecret(kubectl, meta.resourceRefs, policy, { requireIssuer }).catch((error) => { if (!isNotFound(error)) throw error; });
}

async function waitForCertManagerTLSSecret(kubectl, refs, policy) {
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    if (await certManagerTLSSecretExistsOwned(kubectl, refs, policy)) return;
    await new Promise((resolve) => setTimeout(resolve, 1_000));
  }
  throw new Error(`Kubernetes cert-manager TLS secret was not issued: ${refs.ingressTLSSecret}`);
}

async function certManagerTLSSecretExists(kubectl, refs) {
  return kubectl(['get', 'secret', refs.ingressTLSSecret, '-n', refs.namespace, '-o', 'name'], { timeoutMs: 20_000 }).then(() => true).catch((error) => { if (isNotFound(error)) return false; throw error; });
}

async function certManagerTLSSecretExistsOwned(kubectl, refs, policy) {
  try {
    await verifyCertManagerTLSSecret(kubectl, refs, policy);
    return true;
  } catch (error) {
    if (isNotFound(error)) return false;
    throw error;
  }
}

async function verifyCertManagerTLSSecret(kubectl, refs, policy, { requireIssuer = true } = {}) {
  const { stdout } = await kubectl(['get', 'secret', refs.ingressTLSSecret, '-n', refs.namespace, '-o', 'json'], { timeoutMs: 30_000 });
  const secret = JSON.parse(stdout);
  const annotations = secret.metadata?.annotations ?? {};
  // Cleanup after a policy change cannot rely on the currently configured issuer name;
  // certificate name, issuer kind, and secret type still prove cert-manager ownership.
  const issuerMatches = requireIssuer ? annotations['cert-manager.io/issuer-name'] === policy.kubernetes.ingress.tls.clusterIssuer : true;
  if (secret.type !== 'kubernetes.io/tls' || annotations['cert-manager.io/certificate-name'] !== refs.ingressTLSSecret || annotations['cert-manager.io/issuer-kind'] !== 'ClusterIssuer' || !issuerMatches) throw new OwnershipError(`Kubernetes cert-manager TLS secret ownership mismatch for ${refs.ingressTLSSecret}`);
}

async function deleteCertManagerTLSSecret(kubectl, refs, policy, { requireIssuer = true } = {}) {
  if (!await certManagerTLSSecretExists(kubectl, refs)) return;
  await verifyCertManagerTLSSecret(kubectl, refs, policy, { requireIssuer });
  await deleteResource(kubectl, 'secret', refs.ingressTLSSecret, refs.namespace);
}

async function verifyResource(kubectl, kind, name, namespace, expected) {
  const { stdout } = await kubectl(['get', kind, name, '-n', namespace, '-o', 'json'], { timeoutMs: 30_000 });
  const labels = JSON.parse(stdout).metadata?.labels ?? {};
  for (const [key, value] of Object.entries(expected)) if (labels[key] !== value) throw new OwnershipError(`Kubernetes ${kind} ownership mismatch for ${name}: ${key}`);
}

async function resourceExistsOwned(kubectl, kind, name, namespace, expected) {
  try {
    await verifyResource(kubectl, kind.toLowerCase(), name, namespace, expected);
    return true;
  } catch (error) {
    if (isNotFound(error)) return false;
    throw error;
  }
}

function expectedResources(refs) {
  const resources = [['deployment', refs.deployment, 'runtime'], ['service', refs.service, 'service'], ['secret', refs.secret, 'secrets'], ['serviceaccount', refs.serviceAccount, 'service-account'], ['pvc', refs.mutablePVC, 'mutable-storage'], ['pvc', refs.baselinePVC, 'baseline-storage'], ['networkpolicy', refs.networkPolicy, 'network-policy'], ['networkpolicy', refs.seedNetworkPolicy, 'seed-network-policy']];
  if (refs.gatewayDeployment) resources.push(['deployment', refs.gatewayDeployment, 'egress-gateway'], ['service', refs.gatewayService, 'egress-service'], ['networkpolicy', refs.gatewayNetworkPolicy, 'egress-network-policy']);
  if (refs.ingress) resources.push(['ingress', refs.ingress, 'ingress']);
  return resources;
}

function streamArchiveToSeedPod(archivePath, refs, policy, targetDirectory, generation) {
  const args = [...contextArgs(policy), 'exec', '-i', '-n', refs.namespace, `${refs.deployment}-seed`, '--', 'sh', '-lc', KUBERNETES_SEED_EXTRACT_COMMAND, '--', targetDirectory, generation];
  return new Promise((resolve, reject) => {
    const kube = spawn('kubectl', args, { stdio: ['pipe', 'ignore', 'pipe'], windowsHide: true });
    let stderr = '';
    let settled = false;
    const finish = (error) => { if (settled) return; settled = true; clearTimeout(timer); error ? reject(error) : resolve(); };
    const archive = createReadStream(archivePath);
    const timer = setTimeout(() => { archive.destroy(); kube.kill('SIGKILL'); finish(new Error('Kubernetes workspace source seeding timed out')); }, 300_000);
    kube.stderr.on('data', (chunk) => { stderr = `${stderr}${chunk}`.slice(-8192); });
    archive.on('error', finish); kube.on('error', finish);
    kube.on('close', (code) => code === 0 ? finish() : finish(new Error(`Kubernetes source seeding failed: ${stderr}`)));
    archive.pipe(kube.stdin);
  });
}

async function verifyKubernetesSeed(kubectl, seedPod, namespace, targetDirectory, generation) {
  try {
    const { stdout } = await kubectl(['exec', '-n', namespace, seedPod, '--', 'cat', `${targetDirectory}/.openchamber-runtime/source-generation`], { timeoutMs: 30_000 });
    return stdout === generation;
  } catch {
    return false;
  }
}

async function ensurePortForward(meta, port, policy) {
  const existing = portForwards.get(meta.providerResourceID);
  if (existing?.exitCode === null && existing?.signalCode === null) return;
  stopPortForward(meta.providerResourceID);
  if (!(await portAvailable(port))) throw new Error(`Persisted Kubernetes target port is unavailable: ${port}`);
  const args = [...contextArgs(policy), 'port-forward', `service/${meta.resourceRefs.service}`, `${port}:${WORKSPACE_RUNTIME.port}`, '-n', meta.resourceRefs.namespace];
  const child = spawnBackground('kubectl', args);
  portForwards.set(meta.providerResourceID, child);
  await new Promise((resolve) => setTimeout(resolve, 750));
  if (child.exitCode !== null || child.signalCode !== null) { portForwards.delete(meta.providerResourceID); throw new Error(`Kubernetes port-forward failed for ${meta.resourceRefs.service}`); }
}

function stopPortForward(id) {
  const child = portForwards.get(id);
  if (child) child.kill('SIGTERM');
  portForwards.delete(id);
}

function contextArgs(policy) {
  return policy.kubernetes.context ? ['--context', policy.kubernetes.context] : [];
}

function kubernetesConfigured(policy) {
  if (policy.kubernetes.context) return true;
  const kubeconfig = process.env.KUBECONFIG;
  if (typeof kubeconfig === 'string' && kubeconfig.trim()) return true;
  try {
    return existsSync(join(homedir(), '.kube', 'config'));
  } catch {
    return false;
  }
}

function selectorString(selector) {
  return Object.entries(selector).map(([key, value]) => `${key}=${value}`).join(',');
}

async function availableStablePort(providerResourceID) {
  const start = 49152 + Number.parseInt(providerResourceID.slice(-4), 16) % 16384;
  for (let offset = 0; offset < 512; offset += 1) { const port = 49152 + (start - 49152 + offset) % 16384; if (await portAvailable(port)) return port; }
  throw new Error('Unable to allocate a stable loopback port');
}

function portAvailable(port) {
  return new Promise((resolve) => { const server = createServer(); server.once('error', () => resolve(false)); server.listen(port, '127.0.0.1', () => server.close(() => resolve(true))); });
}

const RBAC_PROBE_CONCURRENCY = 8;

/** Runs `task` over `items` with a bounded number in flight, preserving input order. */
async function mapWithConcurrency(items, limit, task) {
  const results = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const index = next++;
      if (index >= items.length) return;
      results[index] = await task(items[index], index);
    }
  });
  await Promise.all(workers);
  return results;
}

function requiredPermissions(policy) {
  const resources = ['pods', 'secrets', 'serviceaccounts', 'persistentvolumeclaims', 'services', 'deployments.apps', 'networkpolicies.networking.k8s.io'];
  const result = resources.flatMap((resource) => ['create', 'get', 'delete'].map((verb) => [verb, resource]));
  result.push(['update', 'secrets']);
  result.push(['list', 'deployments.apps'], ['watch', 'pods'], ['create', 'pods/exec'], ['create', 'pods/portforward']);
  if (policy?.kubernetes?.connectivity === 'ingress') for (const verb of ['create', 'get', 'delete']) result.push([verb, 'ingresses.networking.k8s.io']);
  return result;
}

function identityFromMetadata(meta) {
  return { provider: meta.provider, providerResourceID: meta.providerResourceID, projectID: meta.projectID, controlPlaneWorkspaceID: meta.controlPlaneWorkspaceID, originalControlPlaneWorkspaceID: meta.originalControlPlaneWorkspaceID ?? meta.controlPlaneWorkspaceID };
}

async function readOwnedState(meta) {
  const state = await readWorkspaceState(meta.providerResourceID);
  if (!state || state.provider !== meta.provider || state.projectID !== meta.projectID || state.controlPlaneWorkspaceID !== meta.controlPlaneWorkspaceID) throw new OwnershipError('Kubernetes workspace state identity mismatch');
  return state;
}

function isNotFound(error) {
  return /not found/i.test(error instanceof Error ? error.message : String(error));
}
