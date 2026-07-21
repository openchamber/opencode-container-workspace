import { WORKSPACE_RUNTIME } from './metadata.js';

const RUNTIME_PROXY_PORT = WORKSPACE_RUNTIME.port;
const RUNTIME_OPENCODE_PORT = WORKSPACE_RUNTIME.port + 1;
export const RUNTIME_TOKEN_FILE = `${WORKSPACE_RUNTIME.directory}/.openchamber/token`;
export const KUBERNETES_TOKEN_MOUNT_PATH = '/var/run/openchamber-workspace';
export const KUBERNETES_TOKEN_FILE = `${KUBERNETES_TOKEN_MOUNT_PATH}/token`;
export const BASELINE_COMMAND = `cd ${WORKSPACE_RUNTIME.directory} && if [ ! -d .git ]; then git init >/dev/null && git add . >/dev/null && git -c user.name=OpenChamber -c user.email=openchamber@example.invalid commit -m 'OpenChamber workspace baseline' >/dev/null; fi`;

export const AUTH_PROXY_SCRIPT = String.raw`
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';

const header = (process.env.OPENCHAMBER_WORKSPACE_AUTH_HEADER || '').toLowerCase();
const tokenFile = process.env.OPENCHAMBER_WORKSPACE_AUTH_TOKEN_FILE;
const targetPort = Number(process.env.OPENCHAMBER_WORKSPACE_TARGET_PORT || '4097');
const listenPort = Number(process.env.OPENCHAMBER_WORKSPACE_LISTEN_PORT || '4096');

function readToken() {
  if (!tokenFile) return '';
  return fs.readFileSync(tokenFile, 'utf8').trim();
}

function authorized(req) {
  const expected = readToken();
  return Boolean(header && expected && req.headers[header] === expected);
}

function forwardedHeaders(req) {
  const next = { ...req.headers };
  if (header) delete next[header];
  return next;
}

const server = http.createServer((req, res) => {
  if (!authorized(req)) {
    res.writeHead(401, { 'content-type': 'application/json' });
    res.end('{"error":"workspace runtime authentication required"}');
    return;
  }
  const upstream = http.request({
    hostname: '127.0.0.1',
    port: targetPort,
    method: req.method,
    path: req.url,
    headers: forwardedHeaders(req),
  }, (upstreamRes) => {
    res.writeHead(upstreamRes.statusCode || 502, upstreamRes.headers);
    upstreamRes.pipe(res);
  });
  upstream.on('error', () => {
    if (!res.headersSent) res.writeHead(502, { 'content-type': 'application/json' });
    res.end('{"error":"workspace runtime unavailable"}');
  });
  req.pipe(upstream);
});

server.on('upgrade', (req, socket, head) => {
  if (!authorized(req)) {
    socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
    socket.destroy();
    return;
  }
  const upstream = net.connect(targetPort, '127.0.0.1', () => {
    upstream.write(req.method + ' ' + req.url + ' HTTP/' + req.httpVersion + '\r\n');
    for (const [key, value] of Object.entries(forwardedHeaders(req))) {
      if (Array.isArray(value)) {
        for (const item of value) upstream.write(key + ': ' + item + '\r\n');
      } else if (value !== undefined) {
        upstream.write(key + ': ' + value + '\r\n');
      }
    }
    upstream.write('\r\n');
    if (head.length > 0) upstream.write(head);
    socket.pipe(upstream).pipe(socket);
  });
  upstream.on('error', () => socket.destroy());
});

server.listen(listenPort, '0.0.0.0');
`;

export function runtimeCommand(tokenFile) {
  const proxyPath = '/tmp/openchamber-workspace-auth-proxy.mjs';
  return [
    `cat > ${proxyPath} <<'OPENCHAMBER_PROXY'`,
    AUTH_PROXY_SCRIPT,
    'OPENCHAMBER_PROXY',
    `opencode serve --hostname 127.0.0.1 --port ${RUNTIME_OPENCODE_PORT} &`,
    `exec node ${proxyPath}`,
  ].join('\n');
}

export function runtimeEnvironment(meta, tokenFile) {
  const env = {
    OPENCHAMBER_WORKSPACE_AUTH_HEADER: meta.auth.header,
    OPENCHAMBER_WORKSPACE_AUTH_TOKEN_FILE: tokenFile,
    OPENCHAMBER_WORKSPACE_TARGET_PORT: String(RUNTIME_OPENCODE_PORT),
    OPENCHAMBER_WORKSPACE_LISTEN_PORT: String(RUNTIME_PROXY_PORT),
  };
  const proxy = meta.policy?.egress?.httpProxy;
  if (proxy) {
    env.HTTP_PROXY = proxy;
    env.HTTPS_PROXY = proxy;
    env.http_proxy = proxy;
    env.https_proxy = proxy;
  }
  const noProxy = meta.policy?.egress?.noProxy;
  if (noProxy) {
    env.NO_PROXY = noProxy;
    env.no_proxy = noProxy;
  }
  return env;
}
