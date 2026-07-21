# Development Handoff

Date: 2026-07-21

This repository is the intended home for OpenChamber's OpenCode Secure Workspaces plugin.

## Relationship To OpenChamber

- OpenChamber app repo: `/Users/iivashko/projects/openchamber`
- Source before extraction: `/Users/iivashko/projects/openchamber/packages/opencode-workspace-plugin`
- This repo: `/Users/iivashko/projects/opencode-container-workspace`
- Remote: `git@github.com:openchamber/opencode-container-workspace.git`

This repository is the canonical plugin source after extraction. The package name is fixed to match the repository owner/name decision:

- `@openchamber/opencode-container-workspace`

Package exports:

- `.` -> `./src/plugin.js`
- `./label-id` -> `./src/label-id.js`
- `./policy` -> `./src/policy.js`

Do not add compatibility aliases for the temporary in-monorepo package name; no user workspace settings have shipped with that name.

## Provider Invariants

### Docker

- Runtime container runs on the owned internal Docker bridge `openchamber-secure-workspaces`.
- Runtime container must not publish ports directly.
- A hardened localhost access-proxy sidecar publishes `4096/tcp` only on `127.0.0.1`.
- Runtime and access-proxy use `no-new-privileges` and `--cap-drop ALL`.
- Secure Docker mode requires explicit `egress.httpProxy`.
- Proxy URLs with credentials are rejected.
- Runtime token is file-backed, not a long-lived broad env token.
- Source is copied into managed storage; host source is not mounted writable.

### Kubernetes

- Uses Secret, PVC, Deployment, Service, and optional NetworkPolicy.
- Default mode is `default-deny` NetworkPolicy.
- Egress must be limited to configured DNS CIDRs plus configured proxy CIDR/port.
- Requires explicit `egress.httpProxy`, `egress.proxyCIDR`, and `egress.dnsCIDRs` when NetworkPolicy is enabled.
- `kubectl version --client=true` is used for CLI availability; `kubectl --version` is not portable on kubectl 1.36.
- Source seeding uses tar stream with `tar --no-same-owner` to avoid macOS UID/GID chown failures in hardened pods.

### Apple Container

- Experimental provider; separate from Docker because Apple Container networking differs from Docker bridge networking.
- Uses owned host-only vmnet network `openchamber-secure-workspaces-apple`.
- Apple Container `default` NAT network gave DNS but direct outbound TCP timed out in local smoke; do not rely on a dual-network proxy sidecar model.
- Host-side proxy via vmnet gateway works and is the required egress shape.
- If config uses `http://127.0.0.1:<port>` or `http://localhost:<port>` as `egress.httpProxy`, runtime env is rewritten to the inspected vmnet gateway for the selected network.
- Apple Container does not support dynamic publish syntax like `127.0.0.1::4096`; use a stable high localhost port derived from workspace ID and verify via `container inspect`.
- Runtime publishes only to `127.0.0.1:<port>:4096`.
- `--cap-drop ALL` is verified; exact `no-new-privileges` equivalent is not confirmed.
- Recovery after `container system stop/start` still needs testing.

## Runtime Image

Default intended image:

- `ghcr.io/openchamber/opencode-workspace:1.0.0`

Current blocker:

- `docker pull ghcr.io/openchamber/opencode-workspace:1.0.0` returned registry `denied`.

Local E2E image used so far:

- Docker tag: `openchamber/opencode-workspace-test:1.17.18-arm64`
- Apple Container tag after load: `docker.io/openchamber/opencode-workspace-test:1.17.18-arm64`
- Built from `runtime-image/Dockerfile` in this repository.
- Pins `opencode-ai@1.17.18`.

## Tested So Far

- Docker/Colima E2E with auth, health, isolated network, explicit proxy, mutation, diff export, selective apply, cleanup.
- Kubernetes kind + Calico E2E with real NetworkPolicy enforcement, direct egress blocked, proxy egress allowed, mutation, diff export, selective apply, cleanup.
- External OpenCode compatibility after manual external server restart.
- Apple Container live smoke: create, health, proxy gateway rewrite, mutation via `container exec`, diff export, cleanup.
- Package dry-run previously tightened to exclude test files.

## Not Fully Tested

- Published GHCR release image and multi-arch manifest.
- Windows and Linux platform matrix.
- Packaged Electron GUI flow using the externalized plugin.
- Selective apply conflict and artifact mismatch/expiration scenarios.
- Apple Container recovery after service restart.
- Apple Container exact security equivalent to Docker `no-new-privileges`.

## Immediate Extraction Tasks

1. Run plugin tests/lint locally.
2. Update OpenChamber to depend on this repo/package rather than vendoring source.
3. Re-run OpenChamber web/UI/Electron validation.
4. Continue remaining E2E and platform matrix.
