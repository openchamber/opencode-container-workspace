# OpenChamber OpenCode Container Workspaces

OpenCode workspace plugin that creates isolated workspaces backed by Docker containers or Kubernetes deployments.

The plugin is designed for OpenChamber's Secure Workspaces UI, but it can also be configured directly in OpenCode.

## Requirements

- OpenCode with experimental workspaces enabled.
- A workspace image that contains `opencode`, `git`, and a POSIX shell.
- Docker CLI/daemon for the Docker provider.
- `kubectl` and an existing namespace/context for the Kubernetes provider.

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
        "kubernetes": {
          "namespace": "openchamber-workspaces",
          "connectivity": "port-forward"
        }
      }
    ]
  ]
}
```

OpenChamber writes this config automatically when Secure Workspaces are enabled in Settings.

## Options

- `defaultProvider`: `docker` or `kubernetes`.
- `defaultImage`: runtime image used for new workspaces.
- `allowedImages`: optional allow-list. Supports exact matches and `*` suffix prefixes.
- `requirePinnedImage`: when true, images must use a digest or explicit non-`latest` tag.
- `docker.networkMode`: optional Docker network mode.
- `docker.memoryLimit`: optional Docker memory limit.
- `docker.cpuLimit`: optional Docker CPU limit.
- `kubernetes.context`: optional kube context.
- `kubernetes.namespace`: existing namespace for workspace resources.
- `kubernetes.connectivity`: `port-forward` or `ingress`.
- `kubernetes.ingressBaseUrl`: base URL for ingress mode.
- `kubernetes.storage`: PVC size, default `8Gi`.
- `kubernetes.cpuRequest`, `kubernetes.memoryRequest`, `kubernetes.cpuLimit`, `kubernetes.memoryLimit`: pod resources.
- `retention.preserveOnDelete`: keep workspace storage after removing the workspace.

Environment variables with the `OPENCHAMBER_WORKSPACE_*` prefix can also be used for host-level defaults.

## Behavior

- Each workspace runs its own `opencode serve` inside the container or pod.
- Source files are copied into isolated storage rather than mounted writeable from the host.
- Docker uses a managed volume and local-only port mapping.
- Kubernetes uses Secret, PVC, Deployment, and Service resources in an existing namespace.
- Kubernetes does not create namespaces automatically.
- Exported diffs include tracked, staged, unstaged, binary, and untracked files without mutating the workspace index.

## Export Flow

The plugin implements provider-level `exportDiff`, but OpenCode does not currently expose that method over the experimental workspace HTTP API. OpenChamber provides the user-facing export/review/apply flow on top.
