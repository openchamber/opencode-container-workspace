import dns from 'node:dns/promises';
import http from 'node:http';
import net, { isIP } from 'node:net';
import { pathToFileURL } from 'node:url';

const DEFAULT_PORTS = Object.freeze([80, 443]);

export function parseEgressPolicy(value) {
  const input = typeof value === 'string' ? JSON.parse(value) : value;
  if (!input || typeof input !== 'object' || Array.isArray(input) || input.version !== 1) throw new TypeError('Egress policy version 1 is required');
  const allowedDomains = uniqueStrings(input.allowedDomains ?? []).map(normalizeDomainPattern);
  const allowedCIDRs = uniqueStrings(input.allowedCIDRs ?? []).map(parseCIDR);
  if (allowedCIDRs.some((cidr) => cidr.prefix === 0)) throw new TypeError('Catch-all egress CIDRs are not allowed');
  const allowedPorts = [...new Set(input.allowedPorts ?? DEFAULT_PORTS)].map((port) => {
    const parsed = Number(port);
    if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) throw new TypeError(`Invalid egress port: ${String(port)}`);
    return parsed;
  });
  if (allowedDomains.length === 0 && allowedCIDRs.length === 0) throw new TypeError('Egress policy must allow at least one domain or CIDR');
  return Object.freeze({ version: 1, allowedDomains, allowedCIDRs, allowedPorts });
}

export async function resolveDestination(hostname, policy, resolver = defaultResolver) {
  const host = normalizeHostname(hostname);
  const directFamily = isIP(host);
  const addresses = directFamily ? [{ address: host, family: directFamily }] : await resolver(host);
  if (!Array.isArray(addresses) || addresses.length === 0) throw new Error(`DNS returned no addresses for ${host}`);
  const domainAllowed = !directFamily && policy.allowedDomains.some((pattern) => domainMatches(pattern, host));
  const evaluated = addresses.map(({ address }) => {
    if (!isIP(address)) throw new Error(`DNS returned an invalid address for ${host}`);
    const explicitCIDR = policy.allowedCIDRs.some((cidr) => cidrContains(cidr, address));
    const forbidden = isForbiddenAddress(address);
    return { address, explicitCIDR, forbidden };
  });
  if (evaluated.some((entry) => entry.forbidden && !entry.explicitCIDR)) throw new Error(`Destination resolves to a forbidden address: ${host}`);
  if (!domainAllowed && !evaluated.every((entry) => entry.explicitCIDR)) throw new Error(`Destination is not allowed by egress policy: ${host}`);
  return { host, addresses: evaluated.map((entry) => entry.address) };
}

export function createEgressGateway(policyInput, options = {}) {
  const policy = parseEgressPolicy(policyInput);
  const resolver = options.resolver ?? defaultResolver;
  const logger = options.logger ?? ((event) => process.stdout.write(`${JSON.stringify(event)}\n`));
  const resourceID = options.resourceID ?? 'unknown';
  const server = http.createServer(async (request, response) => {
    let destination;
    try {
      const target = new URL(request.url);
      if (target.protocol !== 'http:') throw new Error('Plain proxy requests must use http; use CONNECT for TLS');
      if (target.username || target.password) throw new Error('Destination credentials are not allowed');
      const port = Number(target.port || 80);
      assertPort(policy, port);
      destination = await resolveDestination(target.hostname, policy, resolver);
      const upstream = http.request({
        host: destination.addresses[0],
        family: isIP(destination.addresses[0]),
        port,
        method: request.method,
        path: `${target.pathname}${target.search}`,
        headers: { ...stripHopByHop(request.headers), host: target.host },
      }, (upstreamResponse) => {
        response.writeHead(upstreamResponse.statusCode ?? 502, stripHopByHop(upstreamResponse.headers));
        upstreamResponse.pipe(response);
      });
      let bytes = 0;
      request.on('data', (chunk) => { bytes += chunk.length; });
      upstream.on('close', () => logDecision(logger, resourceID, destination.host, port, 'allow', bytes));
      upstream.on('error', () => { if (!response.headersSent) response.writeHead(502); response.end(); });
      request.pipe(upstream);
    } catch (error) {
      response.writeHead(403, { 'content-type': 'application/json' });
      response.end('{"error":"destination denied"}');
      logDecision(logger, resourceID, destination?.host ?? safeRequestHost(request.url), 0, 'deny', 0);
    }
  });
  server.on('connect', async (request, client, head) => {
    let host = 'invalid';
    let port = 0;
    try {
      ({ host, port } = parseAuthority(request.url));
      assertPort(policy, port);
      const destination = await resolveDestination(host, policy, resolver);
      const upstream = net.connect({ host: destination.addresses[0], family: isIP(destination.addresses[0]), port });
      let bytes = head.length;
      upstream.once('connect', () => {
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (head.length > 0) upstream.write(head);
        client.on('data', (chunk) => { bytes += chunk.length; });
        client.pipe(upstream).pipe(client);
      });
      upstream.on('close', () => logDecision(logger, resourceID, host, port, 'allow', bytes));
      upstream.on('error', () => client.destroy());
      client.on('error', () => upstream.destroy());
    } catch {
      client.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
      client.destroy();
      logDecision(logger, resourceID, host, port, 'deny', 0);
    }
  });
  return server;
}

export function isForbiddenAddress(address) {
  const family = isIP(address);
  if (family === 4) {
    const value = ipv4Number(address);
    return [
      ['0.0.0.0/8'], ['10.0.0.0/8'], ['100.64.0.0/10'], ['127.0.0.0/8'], ['169.254.0.0/16'],
      ['172.16.0.0/12'], ['192.0.0.0/24'], ['192.0.2.0/24'], ['192.168.0.0/16'], ['198.18.0.0/15'],
      ['198.51.100.0/24'], ['203.0.113.0/24'], ['224.0.0.0/4'], ['240.0.0.0/4'],
    ].some(([cidr]) => cidrContains(parseCIDR(cidr), value));
  }
  if (family === 6) {
    const normalized = ipv6BigInt(address);
    const mappedIPv4 = (normalized >> 32n) === 0xffffn ? Number(normalized & 0xffffffffn) : null;
    if (mappedIPv4 !== null) return isForbiddenAddress(`${mappedIPv4 >>> 24}.${(mappedIPv4 >>> 16) & 255}.${(mappedIPv4 >>> 8) & 255}.${mappedIPv4 & 255}`);
    return ['::/128', '::1/128', '::ffff:0:0/96', '2001::/32', '2001:db8::/32', '2002::/16', 'fc00::/7', 'fe80::/10', 'ff00::/8'].some((cidr) => cidrContains(parseCIDR(cidr), normalized));
  }
  return true;
}

function parseCIDR(value) {
  const [address, prefixText, extra] = String(value).split('/');
  const family = isIP(address);
  const prefix = Number(prefixText);
  const bits = family === 4 ? 32 : family === 6 ? 128 : 0;
  if (extra !== undefined || !family || !Number.isInteger(prefix) || prefix < 0 || prefix > bits) throw new TypeError(`Invalid CIDR: ${String(value)}`);
  return Object.freeze({ source: String(value), family, prefix, value: family === 4 ? BigInt(ipv4Number(address)) : ipv6BigInt(address) });
}

function cidrContains(cidr, address) {
  const family = typeof address === 'number' ? 4 : typeof address === 'bigint' ? 6 : isIP(address);
  if (family !== cidr.family) return false;
  const bits = family === 4 ? 32n : 128n;
  const value = typeof address === 'number' ? BigInt(address) : family === 4 ? BigInt(ipv4Number(address)) : typeof address === 'bigint' ? address : ipv6BigInt(address);
  const shift = bits - BigInt(cidr.prefix);
  return (value >> shift) === (cidr.value >> shift);
}

function ipv4Number(address) {
  return address.split('.').reduce((result, part) => result * 256 + Number(part), 0) >>> 0;
}

function ipv6BigInt(address) {
  const [leftText, rightText = ''] = address.toLowerCase().split('::');
  if (address.split('::').length > 2) throw new TypeError(`Invalid IPv6 address: ${address}`);
  const left = leftText ? leftText.split(':') : [];
  const right = rightText ? rightText.split(':') : [];
  const expandIPv4 = (parts) => parts.flatMap((part) => part.includes('.') ? [((ipv4Number(part) >>> 16) & 0xffff).toString(16), (ipv4Number(part) & 0xffff).toString(16)] : [part]);
  const expandedLeft = expandIPv4(left);
  const expandedRight = expandIPv4(right);
  const missing = 8 - expandedLeft.length - expandedRight.length;
  if (missing < 0 || (!address.includes('::') && missing !== 0)) throw new TypeError(`Invalid IPv6 address: ${address}`);
  const parts = [...expandedLeft, ...Array(missing).fill('0'), ...expandedRight];
  return parts.reduce((result, part) => (result << 16n) | BigInt(Number.parseInt(part || '0', 16)), 0n);
}

function normalizeDomainPattern(value) {
  const normalized = String(value).trim().toLowerCase().replace(/\.$/, '');
  const domain = normalized.startsWith('*.') ? normalized.slice(2) : normalized;
  if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(domain)) throw new TypeError(`Invalid allowed domain: ${String(value)}`);
  return normalized;
}

function normalizeHostname(value) {
  const host = String(value).trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (!host || host.includes('%')) throw new Error('Invalid destination hostname');
  return host;
}

function domainMatches(pattern, host) {
  if (pattern.startsWith('*.')) return host.endsWith(pattern.slice(1)) && host !== pattern.slice(2);
  return host === pattern;
}

function parseAuthority(value) {
  const parsed = new URL(`http://${value}`);
  if (!parsed.hostname || !parsed.port || parsed.username || parsed.password || parsed.pathname !== '/') throw new Error('Invalid CONNECT authority');
  return { host: normalizeHostname(parsed.hostname), port: Number(parsed.port) };
}

function assertPort(policy, port) {
  if (!policy.allowedPorts.includes(port)) throw new Error(`Destination port is not allowed: ${port}`);
}

function stripHopByHop(headers) {
  const next = { ...headers };
  for (const key of ['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade']) delete next[key];
  return next;
}

function safeRequestHost(value) {
  try { return new URL(value).hostname; } catch { return 'invalid'; }
}

function logDecision(logger, resourceID, host, port, decision, bytes) {
  logger({ resourceID, host, port, decision, timestamp: new Date().toISOString(), bytes });
}

function uniqueStrings(values) {
  if (!Array.isArray(values)) throw new TypeError('Egress policy lists must be arrays');
  return [...new Set(values.map(String).filter(Boolean))];
}

async function defaultResolver(host) {
  return dns.lookup(host, { all: true, verbatim: true });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const policy = parseEgressPolicy(process.env.OPENCHAMBER_EGRESS_POLICY);
  const server = createEgressGateway(policy, { resourceID: process.env.OPENCHAMBER_RESOURCE_ID });
  server.listen(Number(process.env.OPENCHAMBER_EGRESS_PORT ?? 3128), '0.0.0.0');
}
