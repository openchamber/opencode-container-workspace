import { beforeEach, describe, expect, it } from 'vitest';
import {
  ENFORCEMENT_VERDICTS,
  lastEnforcementVerdict,
  probeNetworkPolicyEnforcement,
  requireNetworkPolicyEnforcement,
  resetNetworkPolicyEnforcementCache,
} from './network-policy-enforcement.js';

const IMAGE = 'ghcr.io/openchamber/opencode-workspace@sha256:0000000000000000000000000000000000000000000000000000000000000000';

/**
 * Drives the probe by pod role so a test states outcomes ("baseline connected, restricted
 * blocked") instead of scripting a call sequence.
 */
function fakeKubectl({ baseline, restricted }) {
  const calls = [];
  const outcomeFor = (name) => (name.endsWith('-baseline') ? baseline : restricted);
  const kubectl = async (args, options = {}) => {
    calls.push({ args, input: options.input ? JSON.parse(options.input) : undefined });
    if (args[0] === 'create') return { stdout: '' };
    if (args[0] === 'delete') return { stdout: '' };
    if (args[0] === 'get' && args[1] === 'pod') {
      const outcome = outcomeFor(args[2]);
      if (outcome.waiting) return { stdout: JSON.stringify({ status: { phase: 'Pending', containerStatuses: [{ state: { waiting: { reason: outcome.waiting } } }] } }) };
      return { stdout: JSON.stringify({ status: { phase: 'Succeeded', containerStatuses: [{ state: { terminated: { exitCode: outcome.exitCode } } }] } }) };
    }
    throw new Error(`unexpected kubectl call: ${args.join(' ')}`);
  };
  return { kubectl, calls };
}

const deletedKinds = (calls) => calls.filter((call) => call.args[0] === 'delete').map((call) => call.args[1]);
const createdKinds = (calls) => calls.filter((call) => call.args[0] === 'create').map((call) => call.input.kind);

describe('kubernetes network policy enforcement probe', () => {
  beforeEach(() => resetNetworkPolicyEnforcementCache());

  it('reports enforcement when a deny-all policy blocks a reachable address', async () => {
    const { kubectl, calls } = fakeKubectl({ baseline: { exitCode: 0 }, restricted: { exitCode: 1 } });

    const result = await probeNetworkPolicyEnforcement(kubectl, { namespace: 'workspaces', image: IMAGE });

    expect(result.verdict).toBe(ENFORCEMENT_VERDICTS.ENFORCED);
    expect(createdKinds(calls)).toEqual(['Pod', 'NetworkPolicy', 'Pod']);
  });

  it('reports no enforcement when the address stays reachable under a deny-all policy', async () => {
    const { kubectl } = fakeKubectl({ baseline: { exitCode: 0 }, restricted: { exitCode: 0 } });

    const result = await probeNetworkPolicyEnforcement(kubectl, { namespace: 'workspaces', image: IMAGE });

    expect(result.verdict).toBe(ENFORCEMENT_VERDICTS.NOT_ENFORCED);
  });

  it('does not claim enforcement when the address was unreachable to begin with', async () => {
    const { kubectl, calls } = fakeKubectl({ baseline: { exitCode: 1 }, restricted: { exitCode: 1 } });

    const result = await probeNetworkPolicyEnforcement(kubectl, { namespace: 'workspaces', image: IMAGE });

    expect(result.verdict).toBe(ENFORCEMENT_VERDICTS.INCONCLUSIVE);
    // The restricted half is pointless once the reference is unreachable.
    expect(createdKinds(calls)).toEqual(['Pod']);
  });

  it('does not claim enforcement when the probe image cannot be pulled', async () => {
    const { kubectl } = fakeKubectl({ baseline: { waiting: 'ImagePullBackOff' }, restricted: { exitCode: 1 } });

    const result = await probeNetworkPolicyEnforcement(kubectl, { namespace: 'workspaces', image: IMAGE });

    expect(result.verdict).toBe(ENFORCEMENT_VERDICTS.INCONCLUSIVE);
    // The cause is a setting the operator owns, so it is reported apart from anything
    // the probe learned about the cluster's networking.
    expect(result.imageUnavailable).toBe(true);
    expect(result.diagnostics[0]).toMatch(/image could not be pulled/i);
  });

  it('removes every probe resource it created, including after a verdict of no enforcement', async () => {
    const { kubectl, calls } = fakeKubectl({ baseline: { exitCode: 0 }, restricted: { exitCode: 0 } });

    await probeNetworkPolicyEnforcement(kubectl, { namespace: 'workspaces', image: IMAGE });

    expect(deletedKinds(calls).sort()).toEqual(['networkpolicy', 'pod', 'pod']);
  });

  it('refuses the operation when the cluster is proven not to enforce', async () => {
    const { kubectl } = fakeKubectl({ baseline: { exitCode: 0 }, restricted: { exitCode: 0 } });

    await expect(requireNetworkPolicyEnforcement(kubectl, { provider: 'kubernetes', context: 'ctx', namespace: 'workspaces', image: IMAGE }))
      .rejects.toMatchObject({ code: 'WORKSPACE_PROVIDER_NETWORK_POLICY_UNENFORCED' });
  });

  it('allows the operation when the probe is inconclusive but keeps the reason visible', async () => {
    const { kubectl } = fakeKubectl({ baseline: { exitCode: 1 }, restricted: { exitCode: 1 } });

    const result = await requireNetworkPolicyEnforcement(kubectl, { provider: 'kubernetes', context: 'ctx', namespace: 'workspaces', image: IMAGE });

    expect(result.verdict).toBe(ENFORCEMENT_VERDICTS.INCONCLUSIVE);
    expect(lastEnforcementVerdict('ctx', 'workspaces')?.diagnostics[0]).toMatch(/could not be verified/);
  });

  it('reuses a proven verdict instead of probing the same namespace again', async () => {
    const first = fakeKubectl({ baseline: { exitCode: 0 }, restricted: { exitCode: 1 } });
    await requireNetworkPolicyEnforcement(first.kubectl, { provider: 'kubernetes', context: 'ctx', namespace: 'workspaces', image: IMAGE });

    const second = fakeKubectl({ baseline: { exitCode: 0 }, restricted: { exitCode: 1 } });
    const result = await requireNetworkPolicyEnforcement(second.kubectl, { provider: 'kubernetes', context: 'ctx', namespace: 'workspaces', image: IMAGE });

    expect(result.cached).toBe(true);
    expect(second.calls).toHaveLength(0);
  });

  it('re-probes a namespace whose verdict expired rather than trusting a stale pass', async () => {
    const first = fakeKubectl({ baseline: { exitCode: 0 }, restricted: { exitCode: 1 } });
    let clock = 1_000;
    await requireNetworkPolicyEnforcement(first.kubectl, { provider: 'kubernetes', context: 'ctx', namespace: 'workspaces', image: IMAGE, now: () => clock });

    clock += 31 * 60 * 1000;
    const second = fakeKubectl({ baseline: { exitCode: 0 }, restricted: { exitCode: 0 } });
    await expect(requireNetworkPolicyEnforcement(second.kubectl, { provider: 'kubernetes', context: 'ctx', namespace: 'workspaces', image: IMAGE, now: () => clock }))
      .rejects.toMatchObject({ code: 'WORKSPACE_PROVIDER_NETWORK_POLICY_UNENFORCED' });
  });

  it('keeps verdicts separate per namespace so one cluster does not vouch for another', async () => {
    const enforced = fakeKubectl({ baseline: { exitCode: 0 }, restricted: { exitCode: 1 } });
    await requireNetworkPolicyEnforcement(enforced.kubectl, { provider: 'kubernetes', context: 'ctx', namespace: 'workspaces', image: IMAGE });

    const open = fakeKubectl({ baseline: { exitCode: 0 }, restricted: { exitCode: 0 } });
    await expect(requireNetworkPolicyEnforcement(open.kubectl, { provider: 'kubernetes', context: 'ctx', namespace: 'other', image: IMAGE }))
      .rejects.toMatchObject({ code: 'WORKSPACE_PROVIDER_NETWORK_POLICY_UNENFORCED' });
  });

  it('isolates the restricted pod with a policy that denies both directions', async () => {
    const { kubectl, calls } = fakeKubectl({ baseline: { exitCode: 0 }, restricted: { exitCode: 1 } });

    await probeNetworkPolicyEnforcement(kubectl, { namespace: 'workspaces', image: IMAGE });

    const policy = calls.find((call) => call.input?.kind === 'NetworkPolicy').input;
    const restrictedPod = calls.filter((call) => call.input?.kind === 'Pod')[1].input;
    expect(policy.spec.policyTypes.sort()).toEqual(['Egress', 'Ingress']);
    expect(policy.spec.egress).toEqual([]);
    // The policy must actually select the restricted pod, or a pass proves nothing.
    expect(restrictedPod.metadata.labels).toMatchObject(policy.spec.podSelector.matchLabels);
  });
});
