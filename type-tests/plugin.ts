import type { Plugin } from '@opencode-ai/plugin';
import openchamberWorkspacePlugin from '../src/plugin.js';
import { createWorkspaceProviderOperations } from '../src/operations.js';
import type { StreamedWorkspaceExportReceipt, WorkspaceExportArtifactV1 } from '../src/contracts.js';

const plugin: Plugin = openchamberWorkspacePlugin;

void plugin;

const operations = createWorkspaceProviderOperations({ sourceDirectory: '.' });
const artifact: Promise<WorkspaceExportArtifactV1> = operations.exportWorkspace({});
const receipt: Promise<StreamedWorkspaceExportReceipt> = operations.exportWorkspace({}, { write: (_chunk, callback) => callback() });

void artifact;
void receipt;
