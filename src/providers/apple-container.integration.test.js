import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import { WebSocket } from 'ws';
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
    let foreignVolume = false;
    let blockedPortServer;

    try {
      await writeFile(join(sourceDirectory, 'README.md'), 'apple container integration workspace\n');
      const collision = spawnSync(cli, ['network', 'create', '--internal', info.extra.resourceRefs.network], { encoding: 'utf8', windowsHide: true });
      expect(collision.status, collision.stderr || collision.stdout).toBe(0);
      foreignNetwork = true;
      await expect(provider.create(info)).rejects.toThrow(/resource collision/);
      expect(spawnSync(cli, ['network', 'inspect', info.extra.resourceRefs.network], { encoding: 'utf8', windowsHide: true }).status).toBe(0);
      expect(spawnSync(cli, ['network', 'delete', info.extra.resourceRefs.network], { encoding: 'utf8', windowsHide: true }).status).toBe(0);
      foreignNetwork = false;

      const volumeCollision = spawnSync(cli, ['volume', 'create', info.extra.resourceRefs.mutableVolume], { encoding: 'utf8', windowsHide: true });
      expect(volumeCollision.status, volumeCollision.stderr || volumeCollision.stdout).toBe(0);
      foreignVolume = true;
      await expect(provider.create(info)).rejects.toThrow(/resource collision/);
      expect(spawnSync(cli, ['volume', 'inspect', info.extra.resourceRefs.mutableVolume], { encoding: 'utf8', windowsHide: true }).status).toBe(0);
      expect(spawnSync(cli, ['volume', 'delete', info.extra.resourceRefs.mutableVolume], { encoding: 'utf8', windowsHide: true }).status).toBe(0);
      foreignVolume = false;

      const blockedPort = firstStablePort(info.extra.providerResourceID);
      blockedPortServer = createServer();
      await new Promise((resolve, reject) => blockedPortServer.once('error', reject).listen(blockedPort, '127.0.0.1', resolve));
      await provider.create(info);
      created = true;
      let target = await provider.target(info);
      expect(Number(new URL(target.url).port)).not.toBe(blockedPort);
      await closeServer(blockedPortServer);
      blockedPortServer = undefined;
      expect((await fetch(new URL('/global/health', target.url), { headers: target.headers })).ok).toBe(true);
      expect((await fetch(new URL('/global/health', target.url))).status).toBe(401);
      await expectSse(target);
      await expectWebSocketAuthRejection(target);
      await expectPtyWebSocket(target);

      const mutation = spawnSync(cli, [
        'exec', info.extra.resourceRefs.runtime, 'sh', '-lc',
        "printf 'changed\\n' > README.md; printf 'added\\n' > added.txt",
      ], { encoding: 'utf8', windowsHide: true });
      expect(mutation.status, mutation.stderr || mutation.stdout).toBe(0);
      const artifact = await provider.exportWorkspace(info);
      expect(artifact.files.map((entry) => entry.kind)).toEqual(expect.arrayContaining(['modify', 'add']));
      await expect(provider.reconcile(info)).resolves.toMatchObject({ status: 'ready' });

      const oldHeaders = target.headers;
      await expect(provider.rotateCredentials(info)).resolves.toEqual({ rotatedEndpointToken: true, modelAuth: 'revoked' });
      await provider.health(info);
      target = await provider.target(info);
      expect(target.headers['x-openchamber-workspace-token']).not.toBe(oldHeaders['x-openchamber-workspace-token']);
      expect((await fetch(new URL('/global/health', target.url), { headers: oldHeaders })).status).toBe(401);
      expect((await fetch(new URL('/global/health', target.url), { headers: target.headers })).ok).toBe(true);
      await expectSse(target);

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
        if (blockedPortServer) await closeServer(blockedPortServer);
        if (foreignNetwork) spawnSync(cli, ['network', 'delete', info.extra.resourceRefs.network], { encoding: 'utf8', windowsHide: true });
        if (foreignVolume) spawnSync(cli, ['volume', 'delete', info.extra.resourceRefs.mutableVolume], { encoding: 'utf8', windowsHide: true });
        delete process.env.OPENCHAMBER_WORKSPACE_STATE_DIR;
        await rm(sourceDirectory, { recursive: true, force: true });
        await rm(stateDirectory, { recursive: true, force: true });
      }
    }
  }, 600_000);
});

function firstStablePort(providerResourceID) {
  return 49152 + Number.parseInt(providerResourceID.slice(-4), 16) % 16384;
}

async function expectSse(target) {
  const controller = new AbortController();
  const response = await fetch(new URL('/global/event', target.url), { headers: target.headers, signal: controller.signal });
  expect(response.status).toBe(200);
  expect(response.headers.get('content-type')).toContain('text/event-stream');
  const reader = response.body.getReader();
  let timer;
  try {
    const chunk = await Promise.race([
      reader.read(),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('SSE event timed out')), 10_000); }),
    ]);
    expect(chunk.done).toBe(false);
    expect(chunk.value.byteLength).toBeGreaterThan(0);
  } finally {
    clearTimeout(timer);
    controller.abort();
    await reader.cancel().catch(() => {});
  }
}

async function expectWebSocketAuthRejection(target) {
  const url = new URL('/pty/missing/connect', target.url);
  url.protocol = 'ws:';
  const status = await new Promise((resolve, reject) => {
    const socket = new WebSocket(url);
    socket.once('unexpected-response', (_request, response) => {
      resolve(response.statusCode);
      socket.terminate();
    });
    socket.once('open', () => reject(new Error('Unauthenticated WebSocket unexpectedly opened')));
    socket.once('error', (error) => {
      if (!String(error?.message).includes('Unexpected server response')) reject(error);
    });
  });
  expect(status).toBe(401);
}

async function expectPtyWebSocket(target) {
  const directory = '/workspace';
  const createResponse = await fetch(new URL(`/pty?directory=${encodeURIComponent(directory)}`, target.url), {
    method: 'POST',
    headers: { ...target.headers, 'content-type': 'application/json' },
    body: JSON.stringify({ command: 'sh', cwd: directory }),
  });
  expect(createResponse.status).toBe(200);
  const pty = await createResponse.json();
  expect(typeof pty.id).toBe('string');
  try {
    const ticketResponse = await fetch(new URL(`/pty/${encodeURIComponent(pty.id)}/connect-token?directory=${encodeURIComponent(directory)}`, target.url), {
      method: 'POST',
      headers: { ...target.headers, 'x-opencode-ticket': '1', origin: new URL(target.url).origin },
    });
    const ticketBody = await ticketResponse.text();
    expect(ticketResponse.status, ticketBody).toBe(200);
    const { ticket } = JSON.parse(ticketBody);
    expect(typeof ticket).toBe('string');
    const socketUrl = new URL(`/pty/${encodeURIComponent(pty.id)}/connect?directory=${encodeURIComponent(directory)}&ticket=${encodeURIComponent(ticket)}`, target.url);
    socketUrl.protocol = 'ws:';
    const output = await websocketCommand(socketUrl, { ...target.headers, origin: new URL(target.url).origin }, "printf 'workspace-websocket-ok\\n'\r");
    expect(output).toContain('workspace-websocket-ok');
  } finally {
    await fetch(new URL(`/pty/${encodeURIComponent(pty.id)}?directory=${encodeURIComponent(directory)}`, target.url), { method: 'DELETE', headers: target.headers });
  }
}

function websocketCommand(url, headers, command) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(url, { headers });
    let output = '';
    const timer = setTimeout(() => {
      socket.terminate();
      reject(new Error('PTY WebSocket output timed out'));
    }, 15_000);
    socket.once('open', () => socket.send(command));
    socket.on('message', (data) => {
      output += data.toString();
      if (!output.includes('workspace-websocket-ok')) return;
      clearTimeout(timer);
      socket.close();
      resolve(output);
    });
    socket.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

function closeServer(server) {
  if (!server?.listening) return Promise.resolve();
  return new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}
