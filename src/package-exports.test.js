import { describe, expect, it } from 'vitest';
import plugin from '@openchamber/opencode-container-workspace';
import { createWorkspaceProviderOperations } from '@openchamber/opencode-container-workspace/operations';
import { parseProviderKind } from '@openchamber/opencode-container-workspace/contracts';

describe('package exports', () => {
  it('exposes plugin, server operations, and runtime contracts entrypoints', () => {
    expect(plugin).toBeTypeOf('function');
    expect(createWorkspaceProviderOperations).toBeTypeOf('function');
    expect(parseProviderKind('docker')).toBe('docker');
  });
});
