import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { WebSocket, WebSocketServer } from 'ws';
import { closeTransportShim, ensureTransportShim, transportShimStatus } from './transport-shim.js';
import { readWorkspaceState, writeWorkspaceSecret, writeWorkspaceState } from './state-store.js';

const TOKEN_HEADER = 'x-openchamber-workspace-token';

describe('host workspace transport shim', () => {
  let root;
  let sequence;
  const shimIDs = new Set();
  const servers = new Set();

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'workspace-transport-test-'));
    process.env.OPENCHAMBER_WORKSPACE_STATE_DIR = root;
    sequence = 1;
  });

  afterEach(async () => {
    await Promise.all([...shimIDs].map((id) => closeTransportShim(id)));
    await Promise.all([...servers].map((server) => closeServer(server)));
    delete process.env.OPENCHAMBER_WORKSPACE_STATE_DIR;
    await rm(root, { recursive: true, force: true });
  });

  it('streams HTTP and SSE while injecting only the current canonical token', async () => {
    const seen = [];
    let acceptedToken = 'first-token';
    let acceptedOrigin;
    const upstream = await startServer((request, response) => {
      seen.push({ path: request.url, headers: request.headers });
      if (request.headers[TOKEN_HEADER] !== acceptedToken || request.headers.origin !== acceptedOrigin) {
        response.writeHead(401).end('unauthorized');
        return;
      }
      response.setHeader('set-cookie', 'upstream=session');
      response.setHeader('x-openchamber-private', 'hidden');
      if (request.url === '/sse') {
        response.writeHead(200, { 'content-type': 'text/event-stream' });
        response.write('data: one\n\n');
        setTimeout(() => response.end('data: two\n\n'), 15);
        return;
      }
      let body = '';
      request.on('data', (chunk) => { body += chunk; });
      request.on('end', () => response.end(body || 'ok'));
    });
    acceptedOrigin = `http://127.0.0.1:${upstream.port}`;
    const workspace = await fixture(upstream.port, 'first-token');

    const first = await request(workspace.shim.url, '/echo', {
      method: 'POST',
      body: 'payload',
      headers: {
        authorization: 'Bearer client', cookie: 'client=session', forwarded: 'for=attacker', origin: 'https://attacker.example', referer: 'https://attacker.example/path',
        'x-forwarded-host': 'attacker', 'x-opencode-directory': '/foreign', 'x-opencode-ticket': '1',
        'x-openchamber-spoofed': 'spoof', [TOKEN_HEADER]: 'client-token', 'content-length': '7', expect: '100-continue',
      },
    });
    expect(first).toMatchObject({ status: 200, body: 'payload' });
    expect(first.headers['set-cookie']).toBeUndefined();
    expect(first.headers['x-openchamber-private']).toBeUndefined();
    expect(seen[0].headers[TOKEN_HEADER]).toBe('first-token');
    expect(seen[0].headers.origin).toBe(acceptedOrigin);
    expect(seen[0].headers['content-length']).toBe('7');
    expect(seen[0].headers['transfer-encoding']).toBeUndefined();
    expect(seen[0].headers['x-opencode-ticket']).toBe('1');
    for (const name of ['authorization', 'cookie', 'expect', 'forwarded', 'referer', 'x-forwarded-host', 'x-opencode-directory', 'x-openchamber-spoofed']) {
      expect(seen[0].headers[name]).toBeUndefined();
    }

    expect((await request(`http://127.0.0.1:${upstream.port}`, '/echo', { headers: { [TOKEN_HEADER]: 'client-token', origin: acceptedOrigin } })).status).toBe(401);
    acceptedToken = 'rotated-token';
    await writeWorkspaceSecret(workspace.identity.providerResourceID, 'endpoint-token', 'rotated-token');
    const sse = await request(workspace.shim.url, '/sse');
    expect(sse).toMatchObject({ status: 200, body: 'data: one\n\ndata: two\n\n' });
    expect(seen[2].headers[TOKEN_HEADER]).toBe('rotated-token');
    expect(workspace.shim).not.toHaveProperty('headers');
    expect(workspace.shim.url).not.toContain('token');
  });

  it('proxies old-OpenCode-style WebSockets without target headers, preserving binary and subprotocol', async () => {
    let upstreamHeaders;
    let acceptedOrigin;
    const server = await startServer((_request, response) => response.end('http'));
    const wss = new WebSocketServer({ noServer: true, handleProtocols: (protocols) => protocols.has('opencode-v1') ? 'opencode-v1' : false });
    wss.on('headers', (headers) => {
      headers.push('Set-Cookie: forbidden=session');
      headers.push('X-OpenChamber-Private: hidden');
    });
    wss.on('connection', (socket, request) => {
      upstreamHeaders = request.headers;
      socket.on('message', (data, binary) => socket.send(data, { binary }));
    });
    server.server.on('upgrade', (request, socket, head) => {
      if (request.headers[TOKEN_HEADER] !== 'websocket-token' || request.headers.origin !== acceptedOrigin) {
        socket.end('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
        return;
      }
      wss.handleUpgrade(request, socket, head, (websocket) => wss.emit('connection', websocket, request));
    });
    acceptedOrigin = `http://127.0.0.1:${server.port}`;
    const workspace = await fixture(server.port, 'websocket-token');

    const result = await websocketRoundTrip(workspace.shim.url.replace('http:', 'ws:'), Buffer.from([0, 1, 2, 255]), ['opencode-v1'], { origin: 'https://attacker.example', headers: { referer: 'https://attacker.example/path' } });
    expect(result.protocol).toBe('opencode-v1');
    expect(result.binary).toBe(true);
    expect([...result.data]).toEqual([0, 1, 2, 255]);
    expect(upstreamHeaders[TOKEN_HEADER]).toBe('websocket-token');
    expect(upstreamHeaders.origin).toBe(acceptedOrigin);
    expect(upstreamHeaders.referer).toBeUndefined();
    expect(upstreamHeaders['sec-websocket-protocol']).toBe('opencode-v1');
    wss.close();
  });

  it('rejects client-selected destinations and unverified provider targets', async () => {
    const upstream = await startServer((_request, response) => response.end('ok'));
    const workspace = await fixture(upstream.port, 'secret');
    for (const target of ['CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n', 'GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n', 'GET //example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n']) {
      const response = await rawRequest(new URL(workspace.shim.url).port, target);
      expect(response).not.toContain('200 OK');
    }

    const foreign = await createIdentity();
    await expect(ensureTransportShim({
      identity: foreign,
      targetPolicy: { mode: 'loopback' },
      getTarget: async () => ({ type: 'remote', url: 'http://169.254.169.254:80', headers: { [TOKEN_HEADER]: 'token' } }),
    })).rejects.toThrow(/approved loopback/);
    await expect(ensureTransportShim({
      identity: foreign,
      targetPolicy: { mode: 'loopback' },
      getTarget: async () => ({ type: 'remote', url: `http://127.0.0.1:${upstream.port}`, headers: { [TOKEN_HEADER]: 'wrong', authorization: 'extra' } }),
    })).rejects.toThrow(/authentication/);
  });

  it('rejects ambiguous framing and unsafe upgrade handshakes before contacting upstream', async () => {
    let requests = 0;
    const upstream = await startServer((_request, response) => { requests += 1; response.end('ok'); });
    const workspace = await fixture(upstream.port, 'secret');
    const port = new URL(workspace.shim.url).port;
    const attempts = [
      'POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx',
      'POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n',
      'POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n',
      'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\r\n',
      'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\nContent-Length: 0\r\n\r\n',
    ];
    for (const payload of attempts) {
      const response = await rawRequest(port, payload);
      expect(response).not.toContain('101 Switching Protocols');
      expect(response).not.toContain('200 OK');
    }
    expect(requests).toBe(0);
  });

  it('uses normal HTTPS certificate verification and sends provider-host SNI', async () => {
    let requests = 0;
    let servername;
    const upstream = https.createServer({ key: TLS_KEY, cert: TLS_CERT }, (_request, response) => { requests += 1; response.end('unexpected'); });
    upstream.on('tlsClientError', (_error, socket) => { servername = socket.servername; });
    await new Promise((resolve, reject) => upstream.once('error', reject).listen(0, resolve));
    servers.add(upstream);
    const port = upstream.address().port;
    const identity = await createIdentity();
    const shim = await ensureTransportShim({
      identity,
      targetPolicy: { mode: 'https', origin: `https://localhost:${port}` },
      getTarget: async () => ({ type: 'remote', url: `https://localhost:${port}`, headers: { [TOKEN_HEADER]: 'token' } }),
    });

    expect((await request(shim.url, '/')).status).toBe(502);
    expect(requests).toBe(0);
    expect(servername).toBe('localhost');
  });

  it('persists and reuses the exact bound port, failing closed on collision', async () => {
    const upstream = await startServer((_request, response) => response.end('ok'));
    const workspace = await fixture(upstream.port, 'secret');
    const firstPort = Number(new URL(workspace.shim.url).port);
    expect((await readWorkspaceState(workspace.identity.providerResourceID)).transportShimPort).toBe(firstPort);
    await closeTransportShim(workspace.identity.providerResourceID);
    const restarted = await ensureFor(workspace.identity, upstream.port, 'secret');
    expect(Number(new URL(restarted.url).port)).toBe(firstPort);
    await closeTransportShim(workspace.identity.providerResourceID);

    const collision = http.createServer();
    await new Promise((resolve, reject) => collision.once('error', reject).listen(firstPort, '127.0.0.1', resolve));
    servers.add(collision);
    await expect(ensureFor(workspace.identity, upstream.port, 'secret')).rejects.toMatchObject({ code: 'WORKSPACE_TRANSPORT_PORT_COLLISION' });
  });

  it('shares one listener across plugin reloads and rejects cross-workspace registry reassignment', async () => {
    const upstream = await startServer((_request, response) => response.end('ok'));
    const identity = await createIdentity();
    const [left, right] = await Promise.all([ensureFor(identity, upstream.port, 'token'), ensureFor(identity, upstream.port, 'token')]);
    expect(left.url).toBe(right.url);
    expect(transportShimStatus(identity.providerResourceID)).toMatchObject({ listening: true, port: Number(new URL(left.url).port) });

    await expect(ensureTransportShim({
      identity: { ...identity, projectID: 'foreign-project' },
      targetPolicy: { mode: 'loopback' },
      getTarget: async () => target(upstream.port, 'token'),
    })).rejects.toThrow(/reassignment/);
  });

  it('deduplicates provider refresh after connect failure and never replays failed requests', async () => {
    let requestCount = 0;
    const original = await startServer((_request, response) => { requestCount += 1; response.end('original'); });
    const identity = await createIdentity();
    let targetCalls = 0;
    let replacement;
    const getTarget = async () => {
      targetCalls += 1;
      if (targetCalls === 2) {
        await new Promise((resolve) => setTimeout(resolve, 30));
        replacement = await startServer((_request, response) => { requestCount += 1; response.end('replacement'); }, original.port);
      }
      return target(original.port, 'token');
    };
    const shim = await ensureTransportShim({ identity, targetPolicy: { mode: 'loopback' }, getTarget });
    await closeServer(original.server);
    servers.delete(original.server);

    const failed = await Promise.all([request(shim.url, '/one'), request(shim.url, '/two'), request(shim.url, '/three')]);
    expect(failed.every((result) => result.status === 502)).toBe(true);
    expect(requestCount).toBe(0);
    expect(targetCalls).toBe(2);
    expect((await request(shim.url, '/next')).body).toBe('replacement');
    expect(requestCount).toBe(1);
    expect(replacement).toBeDefined();
  });

  it('fails closed when the secret disappears and closes unrefed listeners and sockets', async () => {
    const upstream = await startServer((_request, response) => response.end('ok'));
    const workspace = await fixture(upstream.port, 'secret');
    await rm(join(root, 'workspaces', workspace.identity.providerResourceID, 'secrets', 'endpoint-token'));
    expect((await request(workspace.shim.url, '/')).status).toBe(503);
    expect(transportShimStatus(workspace.identity.providerResourceID).listening).toBe(true);
    await closeTransportShim(workspace.identity.providerResourceID);
    expect(transportShimStatus(workspace.identity.providerResourceID)).toBeNull();
    await expect(request(workspace.shim.url, '/')).rejects.toThrow();
  });

  async function fixture(upstreamPort, tokenValue) {
    const identity = await createIdentity(tokenValue);
    return { identity, shim: await ensureFor(identity, upstreamPort, tokenValue) };
  }

  async function createIdentity(tokenValue = 'token') {
    const suffix = sequence.toString(16).padStart(32, '0');
    sequence += 1;
    const identity = { providerResourceID: `ws-${suffix}`, provider: 'docker', projectID: `project-${suffix}`, controlPlaneWorkspaceID: `control-${suffix}` };
    shimIDs.add(identity.providerResourceID);
    await writeWorkspaceState(identity.providerResourceID, { version: 1, ...identity, lifecycle: 'ready' });
    await writeWorkspaceSecret(identity.providerResourceID, 'endpoint-token', tokenValue);
    return identity;
  }

  function ensureFor(identity, upstreamPort, tokenValue) {
    return ensureTransportShim({ identity, targetPolicy: { mode: 'loopback' }, getTarget: async () => target(upstreamPort, tokenValue) });
  }

  function target(port, tokenValue) {
    return { type: 'remote', url: `http://127.0.0.1:${port}`, headers: { [TOKEN_HEADER]: tokenValue } };
  }

  async function startServer(handler, port = 0) {
    const server = http.createServer(handler);
    await new Promise((resolve, reject) => server.once('error', reject).listen(port, '127.0.0.1', resolve));
    servers.add(server);
    return { server, port: server.address().port };
  }
});

function request(base, path, options = {}) {
  const url = new URL(path, base);
  return new Promise((resolve, reject) => {
    const outgoing = http.request(url, { method: options.method, headers: options.headers }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks).toString() }));
    });
    outgoing.on('error', reject);
    if (options.body) outgoing.write(options.body);
    outgoing.end();
  });
}

function rawRequest(port, payload) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(Number(port), '127.0.0.1', () => socket.end(payload));
    let response = '';
    socket.on('data', (chunk) => { response += chunk; });
    socket.on('end', () => resolve(response));
    socket.on('error', reject);
  });
}

function websocketRoundTrip(url, payload, protocols, options) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(url, protocols, options);
    let result;
    socket.on('open', () => socket.send(payload));
    socket.on('message', (data, binary) => {
      result = { data: Buffer.from(data), binary, protocol: socket.protocol };
      socket.close();
    });
    socket.on('close', () => resolve(result));
    socket.on('error', reject);
  });
}

function closeServer(server) {
  if (!server?.listening) return Promise.resolve();
  server.closeAllConnections?.();
  return new Promise((resolve) => server.close(resolve));
}

const TLS_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDhpGCcLi4ROJPT
U4ICFTIUI/E1FSmPElwj/xbbZXyT8EJibNQ4wveQ9P/VxI4OBI1vKYrja+f9iAjr
xhJU3PoTE/fSawPS7kmNuKSaR3T1fB/gxFJTR5uV28fGYu9wjOOKlHjygjMhh5Ts
hducfjqhxLB5VJCJ0TYRJfd0mbg/l3upselzXnZ7i3qo2VQ+B0sc9SL9Zfg52W60
sNNL9aAuesuvfPa9RczxtDWaEQjQCO+T4+n6H3d5rRQpqwzIbHqJ2SBoPT4JcQm1
hs0zGNCi2dtVnoEuszWi8f74uP8U3h55lt1guZ4HqESDFeG7r5DI8LbGKe54nTR2
XSbJJDfBAgMBAAECggEAZyZVUeBch9vU3BT/SEN3PrTFlg4kDvcGLyB0SvyEbD63
ojX8+CvMr7QIZikyBV94ZnpXtypDheeTqHDGPYw9N853inYIa/spncNsX+jNo1FI
Y2BsAA0qp2Gu3Faq/ckyVc4U0kvJ4wiPgGaa49nipMP9JqINZytAK6uvCVsiWtLh
4afWF/afaWe/7IbMoCnYjI4WOcXPCxyvMBmNzUW4Ek1+QLCO/9sStI1qpPlM0bGt
IW/daMdsvyJKunUJEe7heS0G2gZGcsniH4bq1y+UP9VX8K5nhc5eRND2ceXXuhHc
8D8vJqbhj7LkLgy1AniOLuoQgxTxj5JGirU6ogbdPwKBgQDyXjEar3HYu5l3nHim
ZKlImdOWiDwRrJMYjMHiF+pkXeuScUYEkDa6X/zvPz3SYMCfgR7jt5IIzGzw6fe2
vzBcgDuesj+e95OkpoTWIzTxl1QQjrHSfsTFRE674kYcnv9FI5VZK9UqCIYeVTvn
FghHIpgRS3Rcg5ZQh8bJ4b7KZwKBgQDuVVqAz+x3vfHJdB1er3sDeFikwZa0OA8h
PmVQqwW/yj1vmGp3Njj+PoFD6omTISXyYuuoOPMPfZ3pBreBeEwUd4GtAd9RNVlM
5hYBAeYJtu15I5/4FOK8cW0J0jhFH9/J8QJAjdO95odisKp0z8H8HSkad0QcMz5W
SKkooONjlwKBgHpzWk3ILDW6+ltzI4W1v81dYohgRjELxrmVi/NF7/dLeFRhhGWT
0wKwsmLRydM7bLZpjwiv20k0tym0m6Gp0K47X2PbXMddACwksWJbIUmaEi/XWEIo
KBQeYcUNGi0lq4Tr6G3H9oepDNHQcFZdTEtcUAYU4DJJjS0cnDOtKS6rAoGAUGbx
AjWiw36Lu/d1FQVEDZai6On6ClBDImbnTQB1Dw+ODECx4gej0HmLqDrOMJllMNEY
SQb1UIuDIyLF82J+4AS09YWFLeM+fge88pgOX8abdFuFUu7Q0tu8+iw2GXO4TmsE
5Hw0K4NCtxN8Xa3c9k1sGWaUzqKm6/rVPkSQkX8CgYEA6/PTpGf+nkjTa08dc96w
jLI4t/EP0FInuZIKNNIqBDleYVIO+PK3XHUadQhk8VAotUbaJiQhaKZ/hry5OMg1
+7e7EEEQVnY6RBCM1rw9BTHvdNGERS3O3L3nwWdjKdDtsrHg4LrRYaD1zmnhFuZR
O9rO/a4f3mNJBsq+FP6PhqQ=
-----END PRIVATE KEY-----`;

const TLS_CERT = `-----BEGIN CERTIFICATE-----
MIIDHzCCAgegAwIBAgIUOsggusMtv/+ryGrGiio923bRo2QwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDcyMTIxMjgzN1oXDTM2MDcx
ODIxMjgzN1owFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA4aRgnC4uETiT01OCAhUyFCPxNRUpjxJcI/8W22V8k/BC
YmzUOML3kPT/1cSODgSNbymK42vn/YgI68YSVNz6ExP30msD0u5Jjbikmkd09Xwf
4MRSU0ebldvHxmLvcIzjipR48oIzIYeU7IXbnH46ocSweVSQidE2ESX3dJm4P5d7
qbHpc152e4t6qNlUPgdLHPUi/WX4OdlutLDTS/WgLnrLr3z2vUXM8bQ1mhEI0Ajv
k+Pp+h93ea0UKasMyGx6idkgaD0+CXEJtYbNMxjQotnbVZ6BLrM1ovH++Lj/FN4e
eZbdYLmeB6hEgxXhu6+QyPC2xinueJ00dl0mySQ3wQIDAQABo2kwZzAdBgNVHQ4E
FgQUVaHENptgq1pb7w4IL7XlHV/wBR8wHwYDVR0jBBgwFoAUVaHENptgq1pb7w4I
L7XlHV/wBR8wDwYDVR0TAQH/BAUwAwEB/zAUBgNVHREEDTALgglsb2NhbGhvc3Qw
DQYJKoZIhvcNAQELBQADggEBABhrz5M5+Mjdff1S2RHkkFIkUxl4YrUOSHvMv88i
xjh+6bj6qXyJUdtkl5ZlFZK4LERcyaLir9OhXMFtuDrMGSMsFDQXvbBOZdFaaB3y
qrmjrRwd6A+b4HlMmSNuHOVEcs+iJb4Kvi6BBlRtT9ojQ/DTYS1N68bCnyhLztCs
TXCOvGN466l0SuZyOkS+uMeQr5qYBWqbSBci0sCXi4QOz0iNEYlvUb6v7wDUWJwj
jtGanbPl6t6U2CPzF0Pm+8HLhrdeHxj1ofhzyE8hGMC/eZtTjj+GlNQ1psMPm2Rb
x7fNUA5Dd/sXysGuKw1ytFbwZ18Eh+/hlCyOPvFzROMvuyA=
-----END CERTIFICATE-----`;
