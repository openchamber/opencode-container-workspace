import type { Hooks, PluginInput, PluginOptions } from '@opencode-ai/plugin';

export interface OpenChamberPluginHooks {
  openchamber: {
    secureWorkspaces: {
      registered: boolean;
      reason?: string;
    };
  };
}

export default function openchamberWorkspacePlugin(input: PluginInput, options?: PluginOptions): Promise<Hooks & OpenChamberPluginHooks>;
