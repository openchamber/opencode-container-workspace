# Secure Workspace Plugin Agent Guide

## Purpose

This repository owns the OpenCode plugin and provider runtime for isolated Docker, Kubernetes, and Apple Container workspaces. It also owns runtime/gateway image contents and their release workflow.

The security boundary is part of the product contract. Preserve it even when a simpler provider command or shared image appears to work.

## Read First

Before editing:

1. Read `README.md` for package, provider, image, and security behavior.
2. Read the authoritative [Secure Workspaces specification](https://github.com/openchamber/openchamber/blob/main/docs/SECURE_WORKSPACES_SPECIFICATION.md).
3. When a sibling OpenChamber checkout exists, prefer its current `../openchamber/docs/SECURE_WORKSPACES_SPECIFICATION.md` while developing coordinated changes.
4. Inspect the owning provider/core implementation and its tests before changing behavior.

If these sources materially conflict, stop and resolve the contract instead of silently choosing one.

## Non-Negotiable Invariants

### Identity And Ownership

- Keep control-plane workspace IDs distinct from immutable provider resource IDs.
- Derive canonical resource names; never let metadata select arbitrary resources.
- Verify provider, project, resource ID, role, and original audit identity before target, export, rotation, reconciliation, restart, or deletion.
- Refuse foreign collisions. Absence may be idempotent; ownership mismatch is not absence.

### Isolation And Network

- The runtime executes workspace code. The gateway independently enforces egress. Do not combine these roles.
- Runtime workloads never receive direct fallback egress.
- Gateway workloads never receive project/baseline/secret mounts or workspace credentials.
- Use a managed gateway or a complete explicit external-proxy policy. Missing capability or policy fails closed.
- Apple Container never silently falls back to Docker. Runtime-specific differences remain explicit and tested.

### Images

- Production and allowed images are digest-pinned; do not introduce mutable tags or `latest` defaults.
- Keep runtime and gateway as separate minimal images.
- Preserve non-root runtime execution, read-only root filesystems, dropped capabilities, bounded writable mounts, and provider-specific compensating controls.
- Do not add package managers or build tools to the gateway without a demonstrated runtime need and security review.

### Secrets And Auth

- Keep credentials file-backed and provider-owned. Never place secret values in CLI args, ordinary env, metadata, URLs, diagnostics, or logs.
- Seed provider secret volumes through bounded redacted stdin; never bind-mount private host secret directories.
- Preserve constant-time token authentication for HTTP, SSE, and WebSocket.
- The host transport shim verifies a fixed provider target, strips caller auth/routing headers, rereads the canonical token, and injects it only upstream.

### Lifecycle And Artifacts

- Create uses a durable journal and rolls back only resources proven to have been created by that operation.
- Interrupted creation remains bound to its original source generation.
- Cleanup is ownership-safe, idempotent for absence, explicit about retention, and reports partial failure.
- Reconciliation repairs only ownership-verified resources and reports repairs.
- Snapshots reject traversal, escaping links, special files, mutation, and configured count/size overflow.
- Export remains the bounded binary-safe structured artifact contract; do not add a raw patch fallback.

## Change Discipline

- Make the smallest complete change in the module that owns the behavior.
- Do not add dependencies without explicit approval.
- Update `README.md` when package contracts, provider guarantees, release behavior, or external blockers change.
- Make rollback, retained resources, stale state, retry, and cleanup observable.
- Never let one provider failure become an authoritative empty result for the others.
- Do not weaken core enforcement because a UI or caller currently validates the same input.

Before broadening behavior, answer:

- What state or resource is authoritative?
- How is ownership proven?
- What happens after the first failure?
- What is rolled back, retained, or retryable?
- Which provider/runtime differences are intentional?

## Validation

Use `package.json` scripts as the command source of truth.

For executable changes, run:

```bash
bun run test
bun run lint
bun run type-check
npm pack --dry-run
```

Also run the focused live test for every affected provider. Environment-gated skips are not evidence that the provider works.

Provider/image changes require the applicable evidence:

- Docker: immutable registry digest, lifecycle, auth rejection, export, reconciliation, collision, and cleanup.
- Kubernetes: controlled DNS/egress, NetworkPolicy, port-forward or final HTTPS target, TLS mode, reconciliation, rollback, and cleanup.
- Apple Container: supported macOS host, immutable arm64 image, lifecycle, auth rejection, export, collision, system stop/start recovery, and cleanup.
- Images: `linux/amd64` and `linux/arm64` build/smoke, exact-digest scans, and no fixed HIGH/CRITICAL findings.
- Release: public anonymous exact-digest pulls, signatures, attestations, and recorded runtime/gateway digests.

Static checks alone do not prove isolation, networking, transport, provider lifecycle, or platform behavior.

## Release Rules

- Do not create a release tag while any branch image/provider gate is red.
- Run registry preflight before the first release and prove anonymous pulls for both architectures and both packages.
- GHCR uses repository Actions credentials; never request or store a personal registry token for release automation.
- Sign and verify exact image digests, then pin those digests and the final plugin Git SHA in OpenChamber.
- Keep candidate/preflight tags distinct from semver release tags.

## Red Flags

- Direct runtime internet access or permissive fallback.
- Runtime/gateway role merging.
- Tag-only production image.
- Secret in args, env, metadata, output, or logs.
- Host secret-directory bind mount.
- Resource operation before canonical ownership verification.
- Cleanup that removes control-plane state while provider resources remain.
- Provider failure converted to an empty successful result.
- Platform fallback hidden behind capability detection.
