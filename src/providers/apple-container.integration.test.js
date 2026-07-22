import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import { readPolicy } from '../policy.js';
import { createAppleContainerProvider } from './apple-container.js';

const image = process.env.OPENCHAMBER_APPLE_CONTAINER_WORKSPACE_INTEGRATION_IMAGE;
const cli = process.env.OPENCHAMBER_APPLE_CONTAINER_WORKSPACE_INTEGRATION_CLI ?? 'container';
const proxyUrl = process.env.OPENCHAMBER_APPLE_CONTAINER_WORKSPACE_INTEGRATION_PROXY_URL ?? 'http://127.0.0.1:3128';
const restartSystem = process.env.OPENCHAMBER_APPLE_CONTAINER_WORKSPACE_INTEGRATION_RESTART_SYSTEM === 'true';
const integrationIt = process.platform === 'darwin' && image ? it : it.skip;

describe('Apple Container workspace provider integration', () => {
  integrationIt('creates, exports, reconciles, restarts, and removes an isolated workspace', async () => {
    const sourceDirectory = await mkdtemp(join(process.cwd(), '.openchamber-apple-workspace-source-'));
    const stateDirectory = await mkdtemp(join(process.cwd(), '.openchamber-apple-workspace-state-'));
    process.env.OPENCHAMBER_WORKSPACE_STATE_DIR = stateDirectory;
    const policy = readPolicy({
      defaultImage: image,
      allowedImages: [image],
      egress: { mode: 'external', proxyUrl },
      appleContainer: { cli },
    });
    const provider = createAppleContainerProvider({ policy, sourceDirectory });
    const info = provider.configure({ id: `apple-integration:${Date.now()}`, projectID: 'apple-integration' });
    let created = false;
    let foreignNetwork = false;

    try {
      await writeFile(join(sourceDirectory, 'README.md'), 'apple container integration workspace\n');
      const collision = spawnSync(cli, ['network', 'create', '--internal', info.extra.resourceRefs.network], { encoding: 'utf8', windowsHide: true });
      expect(collision.status, collision.stderr || collision.stdout).toBe(0);
      foreignNetwork = true;
      await expect(provider.create(info)).rejects.toThrow(/resource collision/);
      expect(spawnSync(cli, ['network', 'inspect', info.extra.resourceRefs.network], { encoding: 'utf8', windowsHide: true }).status).toBe(0);
      expect(spawnSync(cli, ['network', 'delete', info.extra.resourceRefs.network], { encoding: 'utf8', windowsHide: true }).status).toBe(0);
      foreignNetwork = false;
      await provider.create(info);
      created = true;
      const target = await provider.target(info);
      expect((await fetch(new URL('/global/health', target.url), { headers: target.headers })).ok).toBe(true);
      expect((await fetch(new URL('/global/health', target.url))).status).toBe(401);

      const mutation = spawnSync(cli, [
        'exec', info.extra.resourceRefs.runtime, 'sh', '-lc',
        "printf 'changed\\n' > README.md; printf 'added\\n' > added.txt",
      ], { encoding: 'utf8', windowsHide: true });
      expect(mutation.status, mutation.stderr || mutation.stdout).toBe(0);
      const artifact = await provider.exportWorkspace(info);
      expect(artifact.files.map((entry) => entry.kind)).toEqual(expect.arrayContaining(['modify', 'add']));
      await expect(provider.reconcile(info)).resolves.toMatchObject({ status: 'ready' });

      if (restartSystem) {
        for (const args of [['system', 'stop'], ['system', 'start']]) {
          const result = spawnSync(cli, args, { encoding: 'utf8', windowsHide: true });
          expect(result.status, result.stderr || result.stdout).toBe(0);
        }
        await expect(provider.reconcile(info)).resolves.toMatchObject({ status: 'ready', repaired: expect.arrayContaining(['runtime-restart']) });
      }
    } finally {
      try {
        if (created) await provider.remove(info);
      } finally {
        if (foreignNetwork) spawnSync(cli, ['network', 'delete', info.extra.resourceRefs.network], { encoding: 'utf8', windowsHide: true });
        delete process.env.OPENCHAMBER_WORKSPACE_STATE_DIR;
        await rm(sourceDirectory, { recursive: true, force: true });
        await rm(stateDirectory, { recursive: true, force: true });
      }
    }
  }, 600_000);
});
