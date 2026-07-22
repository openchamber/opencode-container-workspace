# Development

This repository owns the provider lifecycle, isolation, authentication, reconciliation, export collection, runtime images, and managed egress implementation for OpenChamber Secure Workspaces.

The authoritative production requirements and acceptance gates are maintained in the [OpenChamber Secure Workspaces production specification](https://github.com/openchamber/openchamber/blob/main/docs/SECURE_WORKSPACES_SPECIFICATION.md). Do not duplicate implementation status, release blockers, or alternative architecture decisions in this file.

## Repositories

- Plugin: `openchamber/opencode-container-workspace`
- OpenChamber integration: `openchamber/openchamber`
- Package: `@openchamber/opencode-container-workspace`

The plugin repository is the canonical source for plugin code. OpenChamber consumes an exact reviewed package version or immutable development pin and stages installed package contents for Electron.

## Local Commands

Use `package.json` scripts as the command source of truth:

```sh
bun install
bun run build
bun run type-check
bun run lint
bun run test
```

Provider integration tests require the corresponding local runtime and explicit test configuration. They must never use production credentials or mutate a real project fixture.

## Contribution Rules

- Treat workspace metadata as recovery data, not proof of ownership.
- Keep provider commands, secrets, and resource cleanup inside the plugin boundary.
- Never log credentials, target headers, source contents, or export artifacts.
- Make create, rollback, cleanup, retry, and stale-resource behavior explicit.
- Do not add policy fields that are not enforced by core provider behavior.
- Do not rely on OpenChamber UI checks for provider security.
- Keep OpenCode experimental-contract dependencies isolated and compatibility-tested against the pinned OpenCode release.
- Keep the host transport shim Node-builtins-only and private. Its process-global registry and persisted loopback port are compatibility boundaries for plugin reloads and direct OpenCode installation.
- Do not claim provider or release readiness from mocked tests alone.

## Documentation

Update this file only for repository-local development workflow. Update `README.md` for the package's currently released installation and configuration interface. Update the canonical OpenChamber specification when architecture, security invariants, supported behavior, or release gates change.
