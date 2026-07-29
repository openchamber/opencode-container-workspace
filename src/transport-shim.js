import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import { createHash } from 'node:crypto';
import { AUTH_HEADER, AUTH_SECRET_NAME } from './auth.js';
import { readWorkspaceSecret, readWorkspaceState, withWorkspaceLock, writeWorkspaceState } from './state-store.js';

const REGISTRY_KEY = Symbol.for('openchamber.secure-workspace-transport-shim.v1');
const REGISTRY_VERSION = 2;
const LISTEN_HOST = '127.0.0.1';
const HEADER_TIMEOUT_MS = 10_000;
const MAX_WEBSOCKET_HEADERS = 64 * 1024;
const HOP_BY_HOP = new Set(['connection', 'http2-settings', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade']);
const PRIVATE_HEADERS = new Set(['authorization', 'cookie', 'expect', 'host', 'origin', 'proxy-authorization', 'referer', 'set-cookie', 'forwarded', 'via', 'x-real-ip']);

export async function ensureTransportShim(options) {
  const registry = getRegistry();
  const identity = normalizeIdentity(options.identity);
  const existing = registry.entries.get(identity.providerResourceID);
  if (existing) {
    assertSameIdentity(existing.identity, identity);
    assertSameRuntimeDirectory(existing.runtimeDirectory, options.runtimeDirectory);
    existing.getTarget = options.getTarget;
    existing.targetPolicy = options.targetPolicy;
    await refreshTarget(existing);
    return shimTarget(existing.port);
  }

  const pending = registry.pending.get(identity.providerResourceID);
  if (pending) {
    const entry = await pending;
    assertSameIdentity(entry.identity, identity);
    assertSameRuntimeDirectory(entry.runtimeDirectory, options.runtimeDirectory);
    entry.getTarget = options.getTarget;
    entry.targetPolicy = options.targetPolicy;
    await refreshTarget(entry);
    return shimTarget(entry.port);
  }

  const creation = createTransportShim(registry, identity, options);
  registry.pending.set(identity.providerResourceID, creation);
  try {
    const entry = await creation;
    return shimTarget(entry.port);
  } finally {
    if (registry.pending.get(identity.providerResourceID) === creation) registry.pending.delete(identity.providerResourceID);
  }
}

export async function closeTransportShim(providerResourceID) {
  const registry = getRegistry();
  const pending = registry.pending.get(providerResourceID);
  if (pending) await pending.catch(() => undefined);
  const entry = registry.entries.get(providerResourceID);
  if (!entry) return;
  registry.entries.delete(providerResourceID);
  entry.closed = true;
  for (const socket of entry.sockets) socket.destroy();
  await new Promise((resolve) => entry.server.close(resolve));
}

export function transportShimStatus(providerResourceID) {
  const entry = getRegistry().entries.get(providerResourceID);
  return entry ? { port: entry.port, listening: entry.server.listening, sockets: entry.sockets.size } : null;
}

async function createTransportShim(registry, identity, options) {
  return withWorkspaceLock(identity.providerResourceID, async () => {
    const raced = registry.entries.get(identity.providerResourceID);
    if (raced) {
      assertSameIdentity(raced.identity, identity);
      assertSameRuntimeDirectory(raced.runtimeDirectory, options.runtimeDirectory);
      return raced;
    }

    const state = await readWorkspaceState(identity.providerResourceID);
    assertOwnedState(state, identity);
    const entry = {
      identity,
      runtimeDirectory: normalizeRuntimeDirectory(options.runtimeDirectory),
      getTarget: options.getTarget,
      targetPolicy: options.targetPolicy,
      target: null,
      targetKey: null,
      refreshPromise: null,
      sockets: new Set(),
      closed: false,
      server: null,
      port: null,
    };
    await refreshTarget(entry);
    const server = createServer(entry);
    entry.server = server;
    try {
      entry.port = await listen(server, state.transportShimPort);
      if (state.transportShimPort === undefined) {
        await writeWorkspaceState(identity.providerResourceID, { ...state, transportShimPort: entry.port });
      }
      registry.entries.set(identity.providerResourceID, entry);
      return entry;
    } catch (error) {
      for (const socket of entry.sockets) socket.destroy();
      if (server.listening) await new Promise((resolve) => server.close(resolve));
      throw sanitizeError(error, state.transportShimPort === undefined
        ? 'Unable to reserve the workspace transport shim port'
        : `Persisted workspace transport shim port is unavailable: ${state.transportShimPort}`);
    }
  });
}

function createServer(entry) {
  const server = http.createServer((request, response) => proxyHttp(entry, request, response));
  server.on('upgrade', (request, socket, head) => proxyWebSocket(entry, request, socket, head));
  server.on('connect', (_request, socket) => rejectRaw(socket, 405, 'CONNECT is not supported'));
  server.on('clientError', (_error, socket) => rejectRaw(socket, 400, 'Bad Request'));
  server.on('connection', (socket) => {
    socket.unref();
    entry.sockets.add(socket);
    socket.once('close', () => entry.sockets.delete(socket));
  });
  return server;
}

async function proxyHttp(entry, request, response) {
  if (!validRequestTarget(request.url) || request.method === 'CONNECT' || !validRequestFraming(request)) {
    sendHttpError(response, 400, 'Invalid request target');
    return;
  }

  let token;
  try {
    token = await readWorkspaceSecret(entry.identity.providerResourceID, AUTH_SECRET_NAME);
  } catch {
    sendHttpError(response, 503, 'Workspace authentication is unavailable');
    return;
  }
  if (entry.closed || !entry.target) {
    sendHttpError(response, 503, 'Workspace transport is unavailable');
    return;
  }

  const target = entry.target;
  const client = target.protocol === 'https:' ? https : http;
  const headers = sanitizeHeaders(request.headers);
  headers.origin = target.origin;
  headers[AUTH_HEADER] = token;
  const upstream = client.request({
    protocol: target.protocol,
    hostname: target.hostname,
    port: target.port,
    method: request.method,
    path: rewriteRequestTarget(request.url, entry.runtimeDirectory),
    headers,
  });
  upstream.once('socket', (socket) => socket.unref());
  const deadline = setTimeout(() => upstream.destroy(new Error('upstream response headers timed out')), HEADER_TIMEOUT_MS);
  deadline.unref();
  upstream.once('response', (upstreamResponse) => {
    clearTimeout(deadline);
    response.writeHead(upstreamResponse.statusCode ?? 502, sanitizeHeaders(upstreamResponse.headers, true));
    upstreamResponse.pipe(response);
  });
  upstream.once('error', async () => {
    clearTimeout(deadline);
    await refreshAfterFailure(entry);
    sendHttpError(response, 502, 'Workspace upstream connection failed');
  });
  response.once('close', () => {
    if (!response.writableEnded) upstream.destroy();
  });
  request.pipe(upstream);
}

async function proxyWebSocket(entry, request, clientSocket, head) {
  clientSocket.pause();
  if (!validRequestTarget(request.url) || !validWebSocketHandshake(request)) {
    rejectRaw(clientSocket, 400, 'Invalid WebSocket request');
    return;
  }

  let token;
  try {
    token = await readWorkspaceSecret(entry.identity.providerResourceID, AUTH_SECRET_NAME);
  } catch {
    rejectRaw(clientSocket, 503, 'Workspace authentication is unavailable');
    return;
  }
  if (entry.closed || !entry.target) {
    rejectRaw(clientSocket, 503, 'Workspace transport is unavailable');
    return;
  }

  const target = entry.target;
  const port = Number(target.port || (target.protocol === 'https:' ? 443 : 80));
  const connectOptions = { host: target.hostname, port };
  const upstream = target.protocol === 'https:'
    ? tls.connect({ ...connectOptions, servername: net.isIP(target.hostname) ? undefined : target.hostname })
    : net.connect(connectOptions);
  upstream.unref();
  const deadline = setTimeout(() => upstream.destroy(new Error('upstream response headers timed out')), HEADER_TIMEOUT_MS);
  deadline.unref();
  let responseBuffer = Buffer.alloc(0);
  let settled = false;

  const fail = async () => {
    if (settled) return;
    settled = true;
    clearTimeout(deadline);
    upstream.destroy();
    await refreshAfterFailure(entry);
    rejectRaw(clientSocket, 502, 'Workspace WebSocket connection failed');
  };
  upstream.once('error', fail);
  upstream.once(target.protocol === 'https:' ? 'secureConnect' : 'connect', () => {
    const headers = sanitizeHeaders(request.headers);
    headers.host = target.host;
    headers.connection = 'Upgrade';
    headers.upgrade = 'websocket';
    headers.origin = target.origin;
    headers[AUTH_HEADER] = token;
    upstream.write(`${request.method} ${rewriteRequestTarget(request.url, entry.runtimeDirectory)} HTTP/1.1\r\n${serializeHeaders(headers)}\r\n`);
    if (head.length > 0) upstream.write(head);
  });
  upstream.on('data', onHeaders);

  function onHeaders(chunk) {
    responseBuffer = Buffer.concat([responseBuffer, chunk]);
    if (responseBuffer.length > MAX_WEBSOCKET_HEADERS) {
      fail();
      return;
    }
    const boundary = responseBuffer.indexOf('\r\n\r\n');
    if (boundary === -1) return;
    const parsed = parseWebSocketResponse(responseBuffer.subarray(0, boundary + 4), request.headers['sec-websocket-key'], request.headers['sec-websocket-protocol']);
    if (!parsed) {
      fail();
      return;
    }
    settled = true;
    clearTimeout(deadline);
    upstream.off('data', onHeaders);
    upstream.off('error', fail);
    clientSocket.write(`HTTP/1.1 101 Switching Protocols\r\n${serializeHeaders(parsed.headers)}\r\n`);
    const remainder = responseBuffer.subarray(boundary + 4);
    if (remainder.length > 0) clientSocket.write(remainder);
    upstream.on('error', () => clientSocket.destroy());
    clientSocket.on('error', () => upstream.destroy());
    upstream.pipe(clientSocket).pipe(upstream);
    clientSocket.resume();
  }
}

async function refreshAfterFailure(entry) {
  try {
    await refreshTarget(entry);
  } catch {
    // The current request is never replayed. A later request can retry provider refresh.
  }
}

function refreshTarget(entry) {
  if (entry.refreshPromise) return entry.refreshPromise;
  const refresh = (async () => {
    const providerTarget = await entry.getTarget();
    const token = await readWorkspaceSecret(entry.identity.providerResourceID, AUTH_SECRET_NAME);
    const target = validateProviderTarget(providerTarget, entry.targetPolicy, token);
    const key = `${target.protocol}//${target.host}${target.pathname}`;
    if (entry.targetKey && entry.targetKey !== key) throw new Error('Workspace provider target reassignment was rejected');
    entry.target = target;
    entry.targetKey = key;
  })();
  entry.refreshPromise = refresh;
  return refresh.finally(() => {
    if (entry.refreshPromise === refresh) entry.refreshPromise = null;
  });
}

function validateProviderTarget(target, policy, token) {
  if (!target || target.type !== 'remote' || typeof target.url !== 'string') throw new Error('Workspace provider returned an invalid target');
  const headerEntries = Object.entries(target.headers ?? {});
  if (headerEntries.length !== 1 || headerEntries[0][0].toLowerCase() !== AUTH_HEADER || headerEntries[0][1] !== token) {
    throw new Error('Workspace provider target authentication is invalid');
  }
  let url;
  try {
    url = new URL(target.url);
  } catch {
    throw new Error('Workspace provider returned an invalid target URL');
  }
  if (url.username || url.password || url.hash || url.search || url.pathname !== '/') throw new Error('Workspace provider target URL is not canonical');
  if (policy.mode === 'loopback') {
    if (url.protocol !== 'http:' || url.hostname !== LISTEN_HOST || !url.port) throw new Error('Workspace provider target is not an approved loopback endpoint');
  } else if (policy.mode === 'https') {
    if (url.protocol !== 'https:' || url.origin !== policy.origin) throw new Error('Workspace provider target is not the configured HTTPS endpoint');
  } else {
    throw new Error('Workspace transport target policy is invalid');
  }
  return url;
}

function sanitizeHeaders(headers, response = false) {
  const connectionTokens = new Set(String(headers.connection ?? '').split(',').map((value) => value.trim().toLowerCase()).filter(Boolean));
  const result = {};
  for (const [rawName, value] of Object.entries(headers)) {
    const name = rawName.toLowerCase();
    if (value === undefined || forbiddenHeader(name, response) || HOP_BY_HOP.has(name) || connectionTokens.has(name)) continue;
    result[name] = value;
  }
  return result;
}

function forbiddenHeader(name, response) {
  return PRIVATE_HEADERS.has(name)
    || name.startsWith('x-openchamber-')
    || (name.startsWith('x-opencode-') && name !== 'x-opencode-ticket')
    || name.startsWith('x-forwarded-')
    || (response && name === 'set-cookie');
}

function parseWebSocketResponse(buffer, requestKey, requestedProtocols) {
  const text = buffer.toString('latin1');
  const lines = text.slice(0, -4).split('\r\n');
  if (!/^HTTP\/1\.[01] 101(?: |$)/.test(lines.shift() ?? '')) return null;
  const headers = {};
  for (const line of lines) {
    const separator = line.indexOf(':');
    if (separator <= 0) return null;
    const name = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    if (!/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name) || /[\r\n]/.test(value)) return null;
    if (name === 'upgrade' || name === 'connection' || name.startsWith('sec-websocket-')) headers[name] = value;
  }
  const expectedAccept = typeof requestKey === 'string'
    ? createHash('sha1').update(`${requestKey}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest('base64')
    : '';
  if (headers.upgrade?.toLowerCase() !== 'websocket'
    || !String(headers.connection).toLowerCase().split(',').map((value) => value.trim()).includes('upgrade')
    || headers['sec-websocket-accept'] !== expectedAccept) return null;
  if (headers['sec-websocket-protocol']) {
    const offered = String(requestedProtocols ?? '').split(',').map((value) => value.trim()).filter(Boolean);
    if (!offered.includes(headers['sec-websocket-protocol'])) return null;
  }
  return { headers };
}

function validRequestTarget(value) {
  return typeof value === 'string'
    && value.startsWith('/')
    && !value.startsWith('//')
    && !value.includes('#')
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function rewriteRequestTarget(value, runtimeDirectory) {
  const url = new URL(value, 'http://workspace.invalid');
  if (url.searchParams.has('directory')) url.searchParams.set('directory', runtimeDirectory);
  return `${url.pathname}${url.search}`;
}

function normalizeRuntimeDirectory(value) {
  if (typeof value !== 'string'
    || !value.startsWith('/')
    || value.length > 4096
    || /[\u0000-\u001f\u007f?#]/.test(value)
    || value.split('/').some((segment) => segment === '.' || segment === '..')) {
    throw new Error('Workspace runtime directory is invalid');
  }
  return value;
}

function assertSameRuntimeDirectory(left, right) {
  if (left !== normalizeRuntimeDirectory(right)) throw new Error('Workspace runtime directory reassignment was rejected');
}

function validRequestFraming(request) {
  const contentLengths = rawHeaderValues(request, 'content-length');
  const transferEncodings = rawHeaderValues(request, 'transfer-encoding');
  if (contentLengths.length > 1 || transferEncodings.length > 1 || (contentLengths.length > 0 && transferEncodings.length > 0)) return false;
  if (contentLengths.length === 1 && !/^(?:0|[1-9][0-9]*)$/.test(contentLengths[0].trim())) return false;
  if (transferEncodings.length === 1 && transferEncodings[0].trim().toLowerCase() !== 'chunked') return false;
  return true;
}

function validWebSocketHandshake(request) {
  if (request.method !== 'GET' || !validRequestFraming(request)) return false;
  if (rawHeaderValues(request, 'content-length').length > 0 || rawHeaderValues(request, 'transfer-encoding').length > 0) return false;
  const upgrades = rawHeaderValues(request, 'upgrade');
  const keys = rawHeaderValues(request, 'sec-websocket-key');
  const versions = rawHeaderValues(request, 'sec-websocket-version');
  const connection = String(request.headers.connection ?? '').toLowerCase().split(',').map((value) => value.trim());
  if (upgrades.length !== 1 || upgrades[0].trim().toLowerCase() !== 'websocket' || !connection.includes('upgrade')) return false;
  if (keys.length !== 1 || !validWebSocketKey(keys[0].trim())) return false;
  return versions.length === 1 && versions[0].trim() === '13';
}

function validWebSocketKey(value) {
  if (!/^[A-Za-z0-9+/]{22}==$/.test(value)) return false;
  const decoded = Buffer.from(value, 'base64');
  return decoded.length === 16 && decoded.toString('base64') === value;
}

function rawHeaderValues(request, expectedName) {
  const values = [];
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index].toLowerCase() === expectedName) values.push(request.rawHeaders[index + 1]);
  }
  return values;
}

function serializeHeaders(headers) {
  return `${Object.entries(headers).flatMap(([name, value]) => {
    const values = Array.isArray(value) ? value : [value];
    return values.map((item) => `${name}: ${item}`);
  }).join('\r\n')}\r\n`;
}

function listen(server, persistedPort) {
  return new Promise((resolve, reject) => {
    const onError = (error) => reject(error);
    server.once('error', onError);
    server.listen({ host: LISTEN_HOST, port: persistedPort ?? 0, exclusive: true }, () => {
      server.off('error', onError);
      server.on('error', () => undefined);
      server.unref();
      const address = server.address();
      if (!address || typeof address === 'string' || address.address !== LISTEN_HOST) {
        reject(new Error('transport shim did not bind to IPv4 loopback'));
        return;
      }
      resolve(address.port);
    });
  });
}

function getRegistry() {
  const current = globalThis[REGISTRY_KEY];
  if (current) {
    if (current.version !== REGISTRY_VERSION || !(current.entries instanceof Map) || !(current.pending instanceof Map)) {
      throw new Error('Incompatible process-global workspace transport registry');
    }
    return current;
  }
  const registry = { version: REGISTRY_VERSION, entries: new Map(), pending: new Map() };
  Object.defineProperty(globalThis, REGISTRY_KEY, { value: registry, configurable: false, enumerable: false, writable: false });
  return registry;
}

function normalizeIdentity(identity) {
  const result = {
    providerResourceID: String(identity?.providerResourceID ?? ''),
    provider: String(identity?.provider ?? ''),
    projectID: String(identity?.projectID ?? ''),
    controlPlaneWorkspaceID: String(identity?.controlPlaneWorkspaceID ?? ''),
  };
  if (!/^ws-[a-f0-9]{32}$/.test(result.providerResourceID) || Object.values(result).some((value) => !value)) throw new Error('Workspace transport identity is invalid');
  return Object.freeze(result);
}

function assertSameIdentity(left, right) {
  for (const key of ['providerResourceID', 'provider', 'projectID', 'controlPlaneWorkspaceID']) {
    if (left[key] !== right[key]) throw new Error('Cross-workspace transport reassignment was rejected');
  }
}

function assertOwnedState(state, identity) {
  if (!state) throw new Error('Workspace transport state is missing');
  for (const key of ['providerResourceID', 'provider', 'projectID', 'controlPlaneWorkspaceID']) {
    if (state[key] !== identity[key]) throw new Error('Workspace transport state identity mismatch');
  }
  if (state.transportShimPort !== undefined && (!Number.isInteger(state.transportShimPort) || state.transportShimPort < 1 || state.transportShimPort > 65535)) {
    throw new Error('Persisted workspace transport shim port is invalid');
  }
}

function shimTarget(port) {
  return { type: 'remote', url: `http://${LISTEN_HOST}:${port}` };
}

function sendHttpError(response, status, message) {
  if (response.headersSent || response.destroyed) {
    response.destroy();
    return;
  }
  response.writeHead(status, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', 'content-length': Buffer.byteLength(message) });
  response.end(message);
}

function rejectRaw(socket, status, message) {
  if (socket.destroyed) return;
  socket.end(`HTTP/1.1 ${status} ${message}\r\nConnection: close\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: ${Buffer.byteLength(message)}\r\n\r\n${message}`);
}

function sanitizeError(error, message) {
  const sanitized = new Error(message);
  sanitized.code = error?.code === 'EADDRINUSE' ? 'WORKSPACE_TRANSPORT_PORT_COLLISION' : 'WORKSPACE_TRANSPORT_START_FAILED';
  return sanitized;
}
