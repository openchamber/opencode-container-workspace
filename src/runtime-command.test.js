import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import http from 'node:http';
import { WebSocket, WebSocketServer } from 'ws';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AUTH_PROXY_SCRIPT } from './runtime-command.js';

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
}

function closeServer(server) {
  return new Promise((resolve) => server.close(resolve));
}

function waitForProxy(port) {
  const deadline = Date.now() + 5_000;
  return new Promise((resolve, reject) => {
    const attempt = () => {
      const req = http.request({ host: '127.0.0.1', port, path: '/', timeout: 500 }, (res) => {
        res.resume();
        resolve();
      });
      req.on('error', (error) => {
        if (Date.now() > deadline) reject(error);
        else setTimeout(attempt, 50);
      });
      req.end();
    };
    attempt();
  });
}

function request(port, options = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1',
      port,
      method: options.method ?? 'GET',
      path: options.path ?? '/',
      headers: options.headers,
    }, (res) => {
      let body = '';
      res.on('data', (chunk) => {
        body += chunk.toString('utf8');
      });
      res.on('end', () => resolve({ status: res.statusCode, body, headers: res.headers }));
    });
    req.on('error', reject);
    if (options.body) req.end(options.body);
    else req.end();
  });
}

describe('workspace runtime auth proxy', () => {
  let tempDir;
  let proxyProcess;
  let upstreamServer;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'openchamber-workspace-proxy-'));
  });

  afterEach(async () => {
    if (proxyProcess) {
      proxyProcess.kill('SIGTERM');
      proxyProcess = undefined;
    }
    if (upstreamServer) {
      await closeServer(upstreamServer).catch(() => undefined);
      upstreamServer = undefined;
    }
    if (tempDir) await rm(tempDir, { recursive: true, force: true });
  });

  async function startProxy(targetPort, token = 'secret-token') {
    const tokenFile = join(tempDir, 'token');
    const proxyFile = join(tempDir, 'proxy.mjs');
    await writeFile(tokenFile, token);
    await writeFile(proxyFile, AUTH_PROXY_SCRIPT);
    const listenPort = await new Promise((resolve) => {
      const server = http.createServer();
      server.listen(0, '127.0.0.1', () => {
        const port = server.address().port;
        server.close(() => resolve(port));
      });
    });
    proxyProcess = spawn(process.execPath, [proxyFile], {
      env: {
        ...process.env,
        OPENCHAMBER_WORKSPACE_AUTH_HEADER: 'x-openchamber-workspace-token',
        OPENCHAMBER_WORKSPACE_AUTH_TOKEN_FILE: tokenFile,
        OPENCHAMBER_WORKSPACE_TARGET_PORT: String(targetPort),
        OPENCHAMBER_WORKSPACE_LISTEN_PORT: String(listenPort),
      },
      stdio: 'ignore',
    });
    await waitForProxy(listenPort);
    return listenPort;
  }

  it('rejects missing and invalid tokens before forwarding', async () => {
    upstreamServer = http.createServer((_req, res) => res.end('upstream'));
    const upstreamPort = await listen(upstreamServer);
    const proxyPort = await startProxy(upstreamPort);

    expect((await request(proxyPort)).status).toBe(401);
    expect((await request(proxyPort, { headers: { 'x-openchamber-workspace-token': 'wrong' } })).status).toBe(401);
  });

  it('forwards valid HTTP requests with body and SSE-style chunks', async () => {
    upstreamServer = http.createServer((req, res) => {
      if (req.url === '/sse') {
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        res.write('data: one\n\n');
        res.end('data: two\n\n');
        return;
      }
      let body = '';
      req.on('data', (chunk) => {
        body += chunk.toString('utf8');
      });
      req.on('end', () => res.end(`echo:${body}:${req.headers['x-openchamber-workspace-token'] ?? 'stripped'}`));
    });
    const upstreamPort = await listen(upstreamServer);
    const proxyPort = await startProxy(upstreamPort);
    const headers = { 'x-openchamber-workspace-token': 'secret-token' };

    expect((await request(proxyPort, { method: 'POST', body: 'payload', headers })).body).toBe('echo:payload:stripped');
    expect((await request(proxyPort, { path: '/sse', headers })).body).toBe('data: one\n\ndata: two\n\n');
  });

  it('proxies WebSocket upgrades bidirectionally', async () => {
    upstreamServer = http.createServer();
    const wss = new WebSocketServer({ server: upstreamServer });
    wss.on('connection', (socket, req) => {
      const authHeader = req.headers['x-openchamber-workspace-token'] ?? 'stripped';
      socket.on('message', (message) => socket.send(`echo:${message.toString()}:${authHeader}`));
    });
    const upstreamPort = await listen(upstreamServer);
    const proxyPort = await startProxy(upstreamPort);

    const message = await new Promise((resolve, reject) => {
      const socket = new WebSocket(`ws://127.0.0.1:${proxyPort}`, { headers: { 'x-openchamber-workspace-token': 'secret-token' } });
      socket.on('open', () => socket.send('hello'));
      socket.on('message', (data) => {
        resolve(data.toString());
        socket.close();
      });
      socket.on('error', reject);
    });
    expect(message).toBe('echo:hello:stripped');
  });

  it('returns 502 when the upstream HTTP server is unavailable', async () => {
    const proxyPort = await startProxy(9);
    const result = await request(proxyPort, { headers: { 'x-openchamber-workspace-token': 'secret-token' } });
    expect(result.status).toBe(502);
  });
});
