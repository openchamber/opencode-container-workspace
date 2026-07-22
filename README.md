# OpenChamber OpenCode Container Workspaces

OpenCode workspace plugin for isolated Docker, Kubernetes, and Apple Container workspaces. It can be used directly from OpenCode configuration or through OpenChamber.

The authoritative production and release requirements are in the [Secure Workspaces specification](https://github.com/openchamber/openchamber/blob/main/docs/SECURE_WORKSPACES_SPECIFICATION.md). This package is not production-ready until the external release blockers listed there are complete.

## Package Exports

- `@openchamber/opencode-container-workspace`: OpenCode plugin entrypoint.
- `@openchamber/opencode-container-workspace/operations`: private server-side provider validation, discovery, inspection, cleanup, and export operations.
- `@openchamber/opencode-container-workspace/contracts`: runtime validators and TypeScript declarations for shared contracts.

Provider secrets and arbitrary process helpers are intentionally not exported.

## Requirements

- OpenCode with the compatible experimental workspace registry.
- An explicitly configured digest-pinned runtime image containing OpenCode 1.18.4, Node.js, Git, tar, OpenSSH client, and a POSIX shell.
- Docker CLI/daemon, `kubectl`, or Apple Container as appropriate.
- A digest-pinned managed gateway image or an explicit external egress proxy. The package never silently permits direct runtime egress.
- For Docker or Apple Container, `OPENCHAMBER_WORKSPACE_STATE_DIR` must be on a host path visible to the container runtime because source archives and file-backed secrets are staged there.

There is intentionally no default runtime image until a public signed multi-architecture image exists.
Both image Dockerfiles require `NODE_BASE_IMAGE` as an immutable digest reference. The image workflow pins that multi-architecture digest, the Trivy version, and its ephemeral Docker registry image in source so branch and release builds do not resolve mutable tool or base-image tags.
The Kubernetes live gate uses checksum-verified `kubectl` and k3d binaries, digest-pinned K3s and registry images, and a checksum-verified ingress-nginx manifest with digest-pinned controller images. It validates both port-forward and authenticated HTTPS ingress lifecycle paths before image publication.
The runtime image pins npm `12.0.1` so the required package tooling does not retain the fixed HIGH/CRITICAL vulnerabilities in the base image's npm payload. The gateway has no package-management role and removes npm, Corepack, and Yarn from its final filesystem to reduce its executable and scanner surface.
Before the first release tag, manually dispatch `Workspace Images` with `registry_preflight=true`. The preflight uses only the repository-scoped Actions token to push run-scoped candidates, scan and smoke their exact digests, make both GHCR packages public, log out, and verify unauthenticated multi-architecture pulls. It never creates a semver tag or requires a personal registry credential.

## Configuration

```json
{
  "plugin": [
    [
      "@openchamber/opencode-container-workspace",
      {
        "defaultProvider": "docker",
        "defaultImage": "registry.example/workspace@sha256:<digest>",
        "allowedImages": ["registry.example/workspace@sha256:<digest>"],
        "requirePinnedImage": true,
        "credentials": {
          "modelAuth": "explicit-opencode-auth-content"
        },
        "egress": {
          "mode": "managed",
          "gatewayImage": "registry.example/workspace-egress@sha256:<digest>",
          "preset": "restricted",
          "allowedDomains": [],
          "allowedCIDRs": [],
          "dnsCIDRs": ["10.0.0.53/32"]
        },
        "kubernetes": {
          "context": "workspaces",
          "namespace": "openchamber-workspaces",
          "allowedContexts": ["workspaces"],
          "allowedNamespaces": ["openchamber-workspaces"],
          "connectivity": "port-forward",
          "networkPolicy": "default-deny"
        }
      }
    ]
  ]
}
```

`credentials.modelAuth` defaults to `none`. Setting it to `explicit-opencode-auth-content` is the trusted-policy grant that allows the plugin to parse OpenCode's supplied model authentication and place it in provider secret files. Credential content is never placed in Docker/Apple CLI environment arguments, Kubernetes Deployment environment values, metadata, diagnostics, or adapter targets. Server operations support endpoint-token rotation, model-auth replacement, and revocation.

Kubernetes always requires controlled DNS CIDRs. NetworkPolicy also permits DNS only to standard CoreDNS pods selected by `kube-system` and `k8s-app=kube-dns`, covering clusters that enforce policy after Service translation. External mode additionally requires `egress.proxyUrl` and `egress.proxyCIDR`. Ingress mode requires an ingress class, canonical host template, root path, existing-secret or cert-manager TLS, controller namespace/pod selectors, and allowlisted annotations. Disabled NetworkPolicy remains rejected.

Apple Container is rejected as unsupported outside macOS and never falls back to Docker.

Apple Container live certification is environment-gated. Set `OPENCHAMBER_APPLE_CONTAINER_WORKSPACE_INTEGRATION_IMAGE` to a locally available immutable image reference and run `bunx vitest run src/providers/apple-container.integration.test.js`; set `OPENCHAMBER_APPLE_CONTAINER_WORKSPACE_INTEGRATION_RESTART_SYSTEM=true` to include system stop/start recovery. The restart option stops all Apple Container workloads on the host and is therefore reserved for an isolated certification environment.

## Security Model

- Control-plane workspace IDs and immutable provider resource IDs are distinct.
- Resource names are canonical and rederived; metadata cannot select arbitrary resources.
- Every provider resource is checked for managed, provider, project, resource-ID, and role labels before target, export, or deletion.
- State and secrets are per workspace, mode-restricted, atomically replaced, fsynced, and protected by cross-process locks.
- Docker and Apple Container seed provider-owned secret volumes through redacted stdin; private host secret directories are never bind-mounted into helper containers.
- Create uses a durable journal and rolls back only resources successfully created by that operation. Interrupted creation is bound to the original source generation and refuses to reseed storage from changed host content.
- Cleanup is idempotent for absent resources and refuses foreign resources.
- Mutable storage and an immutable runtime-read-only baseline are seeded from the same source archive, preserving dirty Git and non-Git source content.
- Runtime endpoint authentication uses a random 256-bit file-backed token and constant-time comparison across HTTP, SSE, and WebSocket.
- OpenCode receives a stable, unauthenticated loopback transport URL per workspace. A private host-process shim verifies the provider target, strips client credentials and routing headers, rereads the canonical workspace token for every new HTTP or WebSocket connection, and injects it only toward that workspace's fixed upstream.
- The shim trusts processes running as the same OS user on the host. Containers, Kubernetes ingress/cluster peers, LAN peers, and remote clients remain outside that boundary; provider health and reconciliation continue to use the unchanged authenticated provider target directly.
- Provider process output is bounded and sensitive values are redacted.
- Snapshot traversal detects source mutation, rejects escaping symlinks/hard links/special files, and enforces entry, file, and total byte limits.
- Structured binary-safe artifacts represent additions, modifications, deletions, exact renames, mode changes, symlinks, baseline/result hashes, and bounded blobs for Git and non-Git projects.

Docker uses one internal network per workspace, separate mutable/baseline/secret volumes, a managed policy gateway or fixed-destination external-proxy bridge with no workspace mounts, a hardened non-root runtime, and a mountless access proxy attached to both the internal and default bridges with a loopback-only host bind. The external bridge supports HTTP and certificate-verified HTTPS proxy endpoints; connection deadlines do not terminate healthy idle SSE or WebSocket streams. Kubernetes creates separate PVCs, a Secret, dedicated ServiceAccount, runtime and gateway Deployments/Services, role-scoped NetworkPolicies, optional HTTPS Ingress, hardened security contexts, and authenticated probes. Apple Container supports the external-proxy path with per-workspace host-only networking; managed gateway mode is rejected until multi-network attachment is validated on a supported live host. Apple Container has no exact `no-new-privileges` equivalent.

## Server Operations

```js
import { createWorkspaceProviderOperations } from '@openchamber/opencode-container-workspace/operations';

const operations = createWorkspaceProviderOperations({ policy, sourceDirectory });
const validation = await operations.validateProvider('docker');
const discovery = await operations.discoverProject(projectID);
const recovered = await operations.adoptWorkspace(workspace);
const diagnostics = await operations.reconcileWorkspace(workspace);
await operations.rotateWorkspaceCredentials(workspace, { modelAuth: null });
```

Instantiate operations only in trusted server code using persisted policy. `adoptWorkspace` verifies provider resources and persisted state using the original metadata before atomically rebinding a recovered record's current OpenCode ID; provider resource, project, provider, and original audit identity remain immutable. Cleanup and export perform the same verified adoption automatically. Discovery reports failures per provider instead of converting them to an authoritative empty result.

## Current External Blockers

The host transport shim supports OpenCode versions that omit target headers during WebSocket upgrades, and OpenChamber uses immutable reviewed context handoff instead of warp/detach. Local orchestration compensates known provisional rows and safely adopts a recovered `syncList` row; an upstream stable discovery ID remains preferred but is not required for safe ownership verification. Production release still requires an exact published plugin, public signed multi-architecture runtime and gateway images, updated OpenChamber dependency pins, Apple Container and Kubernetes ingress certification, packaged desktop/mobile platform matrices, and release credentials. See the specification for the complete release gates.
