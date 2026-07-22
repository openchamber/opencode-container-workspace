import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import { readPolicy, SECURE_DOCKER_NETWORK } from '../policy.js';
import { createDockerProvider } from './docker.js';

const image = process.env.OPENCHAMBER_DOCKER_WORKSPACE_INTEGRATION_IMAGE;
const httpProxy = process.env.OPENCHAMBER_DOCKER_WORKSPACE_INTEGRATION_HTTP_PROXY;
const gatewayImage = process.env.OPENCHAMBER_DOCKER_WORKSPACE_INTEGRATION_GATEWAY_IMAGE;
const integrationIt = image && (httpProxy || gatewayImage) ? it : it.skip;

describe('docker workspace provider integration', () => {
  integrationIt('creates a reachable workspace with the default secure Docker network policy', async () => {
    const dockerInfo = spawnSync('docker', ['info'], { stdio: 'ignore', windowsHide: true });
    expect(dockerInfo.status).toBe(0);

    // Keep the bind-mounted fixture under the repository path. Colima on macOS
    // does not reliably expose system temp roots like /var/folders to Docker.
    const sourceDirectory = await mkdtemp(join(process.cwd(), '.openchamber-docker-workspace-source-'));
    const stateDirectory = await mkdtemp(join(process.cwd(), '.openchamber-docker-workspace-state-'));
    process.env.OPENCHAMBER_WORKSPACE_STATE_DIR = stateDirectory;
    const egress = gatewayImage
      ? { mode: 'managed', gatewayImage, preset: 'restricted' }
      : { mode: 'external', proxyUrl: httpProxy, noProxy: '127.0.0.1,localhost' };
    const policy = readPolicy({ defaultImage: image, allowedImages: [image], egress });
    expect(policy.docker.networkMode).toBe(SECURE_DOCKER_NETWORK);
    const provider = createDockerProvider({ policy, sourceDirectory });
    const info = provider.configure({ id: `integration:${Date.now()}`, projectID: 'integration' });
    let passed = false;
    let cleanupCompleted = false;

    try {
      await writeFile(join(sourceDirectory, 'README.md'), 'integration workspace\n');
      await provider.create(info, { OPENCODE_AUTH_CONTENT: '' });
      const target = await provider.target(info);
      const response = await fetch(new URL('/global/health', target.url), { headers: target.headers });

      expect(response.ok).toBe(true);
      const promptCommand = process.env.OPENCHAMBER_DOCKER_WORKSPACE_INTEGRATION_PROMPT_COMMAND;
      if (promptCommand) {
        const result = spawnSync('docker', ['exec', info.extra.resourceRefs.runtime, 'sh', '-lc', promptCommand], { encoding: 'utf8', windowsHide: true });
        expect(result.status, result.stderr || result.stdout).toBe(0);
      }
      passed = true;
    } finally {
      try {
        if (passed || process.env.OPENCHAMBER_DOCKER_WORKSPACE_INTEGRATION_PRESERVE_ON_FAILURE !== 'true') {
          await provider.remove(info);
          cleanupCompleted = true;
        }
      } finally {
        delete process.env.OPENCHAMBER_WORKSPACE_STATE_DIR;
        await rm(sourceDirectory, { recursive: true, force: true });
        if (cleanupCompleted) await rm(stateDirectory, { recursive: true, force: true });
      }
    }
  }, 300_000);
});
