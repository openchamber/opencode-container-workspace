import { describe, expect, it } from 'vitest';
import http from 'node:http';
import { createEgressGateway, isForbiddenAddress, parseEgressPolicy, resolveDestination } from './egress-gateway.js';

describe('managed egress gateway policy', () => {
  const policy = parseEgressPolicy({ version: 1, allowedDomains: ['api.example.com', '*.packages.example.com'], allowedCIDRs: [], allowedPorts: [443] });

  it('allows exact and wildcard subdomains only when every DNS answer is public', async () => {
    await expect(resolveDestination('api.example.com', policy, async () => [{ address: '8.8.8.8', family: 4 }])).resolves.toMatchObject({ addresses: ['8.8.8.8'] });
    await expect(resolveDestination('a.packages.example.com', policy, async () => [{ address: '2606:4700:4700::1111', family: 6 }])).resolves.toBeTruthy();
    await expect(resolveDestination('packages.example.com', policy, async () => [{ address: '8.8.8.8', family: 4 }])).rejects.toThrow(/not allowed/);
  });

  it('blocks DNS rebinding when any answer is private or metadata-addressed', async () => {
    await expect(resolveDestination('api.example.com', policy, async () => [{ address: '8.8.8.8', family: 4 }, { address: '127.0.0.1', family: 4 }])).rejects.toThrow(/forbidden/);
    expect(isForbiddenAddress('169.254.169.254')).toBe(true);
    expect(isForbiddenAddress('10.0.0.1')).toBe(true);
    expect(isForbiddenAddress('::1')).toBe(true);
    expect(isForbiddenAddress('::ffff:127.0.0.1')).toBe(true);
  });

  it('allows private destinations only through explicit CIDRs', async () => {
    const privatePolicy = parseEgressPolicy({ version: 1, allowedDomains: [], allowedCIDRs: ['10.20.0.0/16'], allowedPorts: [443] });
    await expect(resolveDestination('10.20.1.2', privatePolicy)).resolves.toMatchObject({ addresses: ['10.20.1.2'] });
    await expect(resolveDestination('10.21.1.2', privatePolicy)).rejects.toThrow();
  });

  it('rejects malformed and empty policy', () => {
    expect(() => parseEgressPolicy({ version: 1, allowedDomains: [], allowedCIDRs: [] })).toThrow(/at least one/);
    expect(() => parseEgressPolicy({ version: 1, allowedDomains: ['https://example.com'], allowedCIDRs: [] })).toThrow(/Invalid allowed domain/);
  });

  it('forwards HTTP to a pinned allowed address and strips proxy credentials', async () => {
    let proxyAuthorization;
    const upstream = http.createServer((request, response) => { proxyAuthorization = request.headers['proxy-authorization']; response.end('ok'); });
    await listen(upstream);
    const upstreamPort = upstream.address().port;
    const events = [];
    const gateway = createEgressGateway({ version: 1, allowedDomains: [], allowedCIDRs: ['127.0.0.0/8'], allowedPorts: [upstreamPort] }, { logger: (event) => events.push(event), resourceID: 'resource' });
    await listen(gateway);
    try {
      const result = await request(gateway.address().port, `http://127.0.0.1:${upstreamPort}/secret?not-logged=true`);
      expect(result).toBe('ok');
      expect(proxyAuthorization).toBeUndefined();
      expect(events[0]).toMatchObject({ resourceID: 'resource', host: '127.0.0.1', port: upstreamPort, decision: 'allow' });
      expect(JSON.stringify(events)).not.toContain('not-logged');
    } finally {
      await close(gateway); await close(upstream);
    }
  });
});

function listen(server) {
  return new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
}

function close(server) {
  return new Promise((resolve) => server.close(resolve));
}

function request(port, target) {
  return new Promise((resolve, reject) => {
    const value = http.request({ host: '127.0.0.1', port, path: target, headers: { 'proxy-authorization': 'secret' } }, (response) => { let body = ''; response.on('data', (chunk) => { body += chunk; }); response.on('end', () => resolve(body)); });
    value.on('error', reject); value.end();
  });
}
