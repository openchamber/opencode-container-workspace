# OpenChamber OpenCode Container Workspaces

OpenCode workspace plugin that creates isolated workspaces backed by Docker containers, Kubernetes deployments, or Apple Container runtimes.

The plugin is designed for OpenChamber's Secure Workspaces UI, but it can also be configured directly in OpenCode.

## Requirements

- OpenCode with experimental workspaces enabled.
- A workspace image that contains `opencode`, `git`, and a POSIX shell.
- Docker CLI/daemon for the Docker provider.
- `kubectl` and an existing namespace/context for the Kubernetes provider.
- Apple Container CLI for the experimental `apple-container` provider on supported macOS hosts.

## Install

```sh
npm install @openchamber/opencode-container-workspace
```

Then add the plugin to your OpenCode config. OpenChamber writes this config automatically when Secure Workspaces are enabled in Settings.

## OpenCode Config

```json
{
  "plugin": [
    [
      "@openchamber/opencode-container-workspace",
      {
        "defaultProvider": "docker",
        "defaultImage": "ghcr.io/openchamber/opencode-workspace:1.0.0",
        "requirePinnedImage": true,
        "allowedImages": ["ghcr.io/openchamber/opencode-workspace:1.0.0"],
        "docker": {},
        "appleContainer": {},
        "kubernetes": {
          "namespace": "openchamber-workspaces",
          "connectivity": "port-forward",
          "networkPolicy": "default-deny"
        },
        "egress": {
          "httpProxy": "http://proxy.openchamber.svc.cluster.local:3128",
          "proxyCIDR": "10.0.0.10/32",
          "dnsCIDRs": ["10.0.0.53/32"],
          "noProxy": "127.0.0.1,localhost"
        }
      }
    ]
  ]
}
```

## Options

- `defaultProvider`: `docker`, `kubernetes`, or `apple-container`.
- `defaultImage`: runtime image used for new workspaces.
- `allowedImages`: optional allow-list. Supports exact matches and `*` suffix prefixes.
- `requirePinnedImage`: when true, images must use a digest or explicit non-`latest` tag.
- `docker.networkMode`: `openchamber-secure-workspaces` by default. The plugin creates this as an owned internal bridge network so local-only host port publishing works while container egress through that network is denied. `none` is supported for direct plugin use but makes the runtime unreachable through host port publishing.
- `docker.allowedNetworks`: explicit allow-list for additional Docker networks that may be attached to workspace containers, such as `bridge` for installations that intentionally permit broader connectivity.
- `docker.memoryLimit`: optional Docker memory limit.
- `docker.cpuLimit`: optional Docker CPU limit.
- `appleContainer.cli`: Apple Container CLI path, default `container`.
- `appleContainer.networkMode`: `openchamber-secure-workspaces-apple` by default. The plugin creates this as an owned host-only vmnet network.
- `appleContainer.memoryLimit`: optional Apple Container memory limit.
- `appleContainer.cpuLimit`: optional Apple Container CPU limit.
- `kubernetes.context`: optional kube context.
- `kubernetes.namespace`: existing namespace for workspace resources.
- `kubernetes.connectivity`: `port-forward` or `ingress`.
- `kubernetes.networkPolicy`: `default-deny` by default. The plugin creates a per-workspace NetworkPolicy with no ingress and egress limited to configured DNS CIDRs plus the configured proxy CIDR/port. Set `disabled` only when the cluster provides equivalent isolation externally.
- `kubernetes.ingressBaseUrl`: base URL for ingress mode.
- `kubernetes.storage`: PVC size, default `8Gi`.
- `kubernetes.cpuRequest`, `kubernetes.memoryRequest`, `kubernetes.cpuLimit`, `kubernetes.memoryLimit`: pod resources.
- `egress.httpProxy`: required for default isolated Docker, Kubernetes, and Apple Container workspaces. Runtime provider/model traffic is sent through this explicit proxy via `HTTP_PROXY`/`HTTPS_PROXY`. For Apple Container, configure a host-local proxy URL such as `http://127.0.0.1:3128`; the plugin rewrites it to the inspected vmnet gateway inside the runtime.
- `egress.proxyCIDR`: required for Kubernetes `default-deny`; CIDR containing the approved egress proxy.
- `egress.dnsCIDRs`: required for Kubernetes `default-deny`; CIDRs for DNS servers the workspace may query.
- `egress.noProxy`: optional `NO_PROXY` value for local/runtime bypasses.
- `retention.preserveOnDelete`: keep workspace storage after removing the workspace.

Environment variables with the `OPENCHAMBER_WORKSPACE_*` prefix can also be used for host-level defaults.

## Behavior

- Each workspace runs its own `opencode serve` inside the container or pod.
- Source files are copied into isolated storage rather than mounted writeable from the host.
- Docker uses a managed volume, an owned internal bridge network, and local-only port mapping.
- Apple Container uses a managed volume, an owned host-only vmnet network, explicit host-proxy egress, and local-only port publishing. This provider is experimental and remains separate from Docker because Apple Container networking differs from Docker bridge networking.
- Kubernetes uses Secret, PVC, Deployment, and Service resources in an existing namespace.
- Kubernetes creates a default-deny NetworkPolicy for each workspace unless explicitly disabled. In default-deny mode, egress is limited to configured DNS CIDRs and the configured proxy CIDR/port.
- Kubernetes does not create namespaces automatically.
- Exported diffs include tracked, staged, unstaged, binary, and untracked files without mutating the workspace index.

## Connectivity Smoke Tests

The Docker integration test is opt-in because it needs a real workspace image and provider credentials. Set `OPENCHAMBER_DOCKER_WORKSPACE_INTEGRATION_IMAGE` plus `OPENCHAMBER_DOCKER_WORKSPACE_INTEGRATION_HTTP_PROXY`; optionally set `OPENCHAMBER_DOCKER_WORKSPACE_INTEGRATION_PROMPT_COMMAND` to a command that performs a real provider prompt from inside the workspace container. The test runs that command with `docker exec` after `/global/health` succeeds.

## Export Flow

The plugin implements provider-level `exportDiff`, but OpenCode does not currently expose that method over the experimental workspace HTTP API. OpenChamber provides the user-facing export/review/apply flow on top.
