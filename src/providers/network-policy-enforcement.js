import { randomBytes } from 'node:crypto';
import { ProviderUnavailableError } from '../errors.js';

/**
 * A cluster accepts NetworkPolicy objects whether or not its CNI enforces them. Where
 * nothing enforces, every workspace policy this provider writes is inert: the runtime
 * reaches the whole cluster network and the internet directly, the egress allowlist
 * means nothing, and every surface still reports the workspace as isolated. The only
 * way to know is to observe enforcement, so this probes it directly.
 *
 * Two pods run the same TCP reachability check against the in-cluster API server
 * address, which kubelet injects into every pod. The first runs unrestricted to prove
 * the target is reachable at all; the second runs under a deny-all policy. Two probes,
 * not one, because a single blocked probe cannot distinguish an enforced policy from a
 * target that was never reachable.
 */

const ENFORCED_TTL_MS = 30 * 60 * 1000;
// Re-probed sooner than a proven verdict: an inconclusive result usually means something
// transient about the cluster, and it should not be reported as current for half an hour.
const INCONCLUSIVE_TTL_MS = 10 * 60 * 1000;
const PROBE_TIMEOUT_MS = 210_000;
const POLL_INTERVAL_MS = 1_000;

export const ENFORCEMENT_VERDICTS = Object.freeze({
  ENFORCED: 'enforced',
  NOT_ENFORCED: 'not-enforced',
  INCONCLUSIVE: 'inconclusive',
});

// A pod can start before the CNI has programmed a policy that selects it, so a single
// connection attempt races enforcement and a lucky early packet looks like a cluster
// that enforces nothing. Enforcement latches: once it applies it stays, so the probe
// samples across a window and treats any blocked attempt as proof of enforcement, while
// only an unbroken run of successes across the whole window proves the absence of it.
const PROBE_WINDOW_MS = 20_000;
const PROBE_ATTEMPT_INTERVAL_MS = 2_000;
const PROBE_CONNECT_TIMEOUT_MS = 5_000;

// Exit 0 means "reachable", exit 1 means "blocked" — the probe reports what the network
// did, and the caller decides which of those is the good news.
const reachabilityCommand = (mode) => [
  'node', '-e',
  "const net=require('node:net');" +
  "const host=process.env.KUBERNETES_SERVICE_HOST;" +
  "const port=Number(process.env.KUBERNETES_SERVICE_PORT_HTTPS||process.env.KUBERNETES_SERVICE_PORT||443);" +
  "if(!host)process.exit(3);" +
  `const mode=${JSON.stringify(mode)};` +
  `const deadline=Date.now()+${PROBE_WINDOW_MS};` +
  "const attempt=()=>new Promise((resolve)=>{" +
  "const socket=net.connect({host,port});" +
  `socket.setTimeout(${PROBE_CONNECT_TIMEOUT_MS});` +
  "socket.on('connect',()=>{socket.destroy();resolve(true)});" +
  "socket.on('timeout',()=>{socket.destroy();resolve(false)});" +
  "socket.on('error',()=>resolve(false));});" +
  "(async()=>{for(;;){" +
  "const reachable=await attempt();" +
  // Baseline stops at the first success: one reachable moment is all it must establish.
  "if(mode==='baseline'&&reachable)process.exit(0);" +
  // Restricted stops at the first failure: enforcement latches, so one block settles it.
  "if(mode==='restricted'&&!reachable)process.exit(1);" +
  "if(Date.now()>=deadline)process.exit(mode==='baseline'?1:0);" +
  `await new Promise((resolve)=>setTimeout(resolve,${PROBE_ATTEMPT_INTERVAL_MS}));` +
  "}})();",
];

const lastVerdicts = new Map();

const cacheKey = (context, namespace) => `${context ?? ''}|${namespace}`;

/**
 * The last verdict for a namespace, so a cheap readiness check can report what an
 * earlier create already established without re-running the probe itself.
 */
export function lastEnforcementVerdict(context, namespace, now = Date.now) {
  const entry = lastVerdicts.get(cacheKey(context, namespace));
  if (!entry || entry.expiresAt <= now()) return null;
  return { verdict: entry.verdict, diagnostics: entry.diagnostics };
}

function probePod(name, namespace, labels, image, mode) {
  return {
    apiVersion: 'v1',
    kind: 'Pod',
    metadata: { name, namespace, labels },
    spec: {
      restartPolicy: 'Never',
      automountServiceAccountToken: false,
      enableServiceLinks: false,
      securityContext: { runAsNonRoot: true, runAsUser: 1000, runAsGroup: 1000, seccompProfile: { type: 'RuntimeDefault' } },
      containers: [{
        name: 'probe',
        image,
        command: reachabilityCommand(mode),
        securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: ['ALL'] } },
        resources: { requests: { cpu: '50m', memory: '64Mi' }, limits: { cpu: '500m', memory: '256Mi' } },
      }],
    },
  };
}

function denyAllPolicy(name, namespace, labels, podLabels) {
  return {
    apiVersion: 'networking.k8s.io/v1',
    kind: 'NetworkPolicy',
    metadata: { name, namespace, labels },
    spec: { podSelector: { matchLabels: podLabels }, policyTypes: ['Ingress', 'Egress'], ingress: [], egress: [] },
  };
}

/** Waits for a terminal container state and returns its exit code, or a blocking reason. */
async function runProbePod(kubectl, manifest, namespace, deadline, now) {
  const name = manifest.metadata.name;
  await kubectl(['create', '-f', '-'], { timeoutMs: 60_000, input: JSON.stringify(manifest) });
  for (;;) {
    if (now() > deadline) return { blocked: `probe pod ${name} did not finish in time` };
    const { stdout } = await kubectl(['get', 'pod', name, '-n', namespace, '-o', 'json'], { timeoutMs: 20_000 });
    const status = JSON.parse(stdout).status ?? {};
    const container = (status.containerStatuses ?? [])[0];
    const terminated = container?.state?.terminated;
    if (typeof terminated?.exitCode === 'number') return { exitCode: terminated.exitCode };
    const waiting = container?.state?.waiting;
    // An unpullable image never terminates, so treat it as a probe failure rather than
    // waiting out the whole deadline for a pod that cannot run.
    if (waiting && /ErrImagePull|ImagePullBackOff|InvalidImageName|CreateContainerConfigError/i.test(waiting.reason ?? '')) {
      return { blocked: `probe pod ${name} cannot start: ${waiting.reason}${waiting.message ? ` (${waiting.message})` : ''}` };
    }
    if (status.phase === 'Failed' && !terminated) return { blocked: `probe pod ${name} failed: ${status.reason ?? 'unknown reason'}` };
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  }
}

/**
 * Returns `{ verdict, diagnostics }` without throwing for a cluster that simply does not
 * enforce; the caller decides what a verdict means for the operation it is guarding.
 */
export async function probeNetworkPolicyEnforcement(kubectl, { namespace, image, now = Date.now }) {
  const suffix = randomBytes(4).toString('hex');
  const baseName = `openchamber-isolation-probe-${suffix}`;
  const labels = { 'openchamber.io/component': 'isolation-probe', 'openchamber.io/probe-id': suffix };
  const restrictedLabels = { ...labels, 'openchamber.io/probe-role': 'restricted' };
  const created = [];
  const deadline = now() + PROBE_TIMEOUT_MS;
  try {
    const baseline = await runProbePod(kubectl, probePod(`${baseName}-baseline`, namespace, { ...labels, 'openchamber.io/probe-role': 'baseline' }, image, 'baseline'), namespace, deadline, now);
    created.push(['pod', `${baseName}-baseline`]);
    if (baseline.blocked) return { verdict: ENFORCEMENT_VERDICTS.INCONCLUSIVE, diagnostics: [`Network isolation could not be verified: ${baseline.blocked}.`] };
    if (baseline.exitCode !== 0) {
      return {
        verdict: ENFORCEMENT_VERDICTS.INCONCLUSIVE,
        diagnostics: ['Network isolation could not be verified: the reference address was already unreachable from an unrestricted pod, so enforcement cannot be distinguished from a blocked network.'],
      };
    }

    await kubectl(['create', '-f', '-'], { timeoutMs: 60_000, input: JSON.stringify(denyAllPolicy(baseName, namespace, labels, restrictedLabels)) });
    created.push(['networkpolicy', baseName]);
    const restricted = await runProbePod(kubectl, probePod(`${baseName}-restricted`, namespace, restrictedLabels, image, 'restricted'), namespace, deadline, now);
    created.push(['pod', `${baseName}-restricted`]);
    if (restricted.blocked) return { verdict: ENFORCEMENT_VERDICTS.INCONCLUSIVE, diagnostics: [`Network isolation could not be verified: ${restricted.blocked}.`] };
    if (restricted.exitCode === 0) return { verdict: ENFORCEMENT_VERDICTS.NOT_ENFORCED, diagnostics: [] };
    return { verdict: ENFORCEMENT_VERDICTS.ENFORCED, diagnostics: [] };
  } finally {
    for (const [kind, name] of created) {
      await kubectl(['delete', kind, name, '-n', namespace, '--ignore-not-found=true', '--wait=false'], { timeoutMs: 30_000 }).catch(() => {});
    }
  }
}

/**
 * Fails closed when the cluster is proven not to enforce, and reports an inconclusive
 * probe as a diagnostic instead: refusing every cluster whose reference address happens
 * to be unreachable would deny working clusters without making anyone safer.
 */
export async function checkNetworkPolicyEnforcement(kubectl, { context, namespace, image, now = Date.now, force = false }) {
  const key = cacheKey(context, namespace);
  const cached = lastVerdicts.get(key);
  if (!force && cached && cached.expiresAt > now() && cached.verdict === ENFORCEMENT_VERDICTS.ENFORCED) {
    return { verdict: ENFORCEMENT_VERDICTS.ENFORCED, diagnostics: [], cached: true };
  }

  const result = await probeNetworkPolicyEnforcement(kubectl, { namespace, image, now });
  if (result.verdict === ENFORCEMENT_VERDICTS.NOT_ENFORCED) lastVerdicts.delete(key);
  else lastVerdicts.set(key, { verdict: result.verdict, diagnostics: result.diagnostics, expiresAt: now() + (result.verdict === ENFORCEMENT_VERDICTS.ENFORCED ? ENFORCED_TTL_MS : INCONCLUSIVE_TTL_MS) });
  return { ...result, cached: false };
}

export async function requireNetworkPolicyEnforcement(kubectl, { provider, context, namespace, image, now = Date.now }) {
  const result = await checkNetworkPolicyEnforcement(kubectl, { context, namespace, image, now });
  if (result.verdict === ENFORCEMENT_VERDICTS.NOT_ENFORCED) {
    throw new ProviderUnavailableError(
      `Kubernetes cluster does not enforce NetworkPolicy in namespace ${namespace}, so workspace network isolation would not hold. Install a CNI that enforces NetworkPolicy (for example Calico or Cilium) or use a namespace on a cluster that does.`,
      { provider, code: 'WORKSPACE_PROVIDER_NETWORK_POLICY_UNENFORCED' },
    );
  }
  return result;
}

export function resetNetworkPolicyEnforcementCache() {
  lastVerdicts.clear();
}
