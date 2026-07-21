import http from 'node:http';
import { afterEach, describe, expect, it } from 'vitest';
import { waitForHttpHealth } from './health.js';

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
}

function closeServer(server) {
  return new Promise((resolve) => server.close(resolve));
}

describe('workspace health checks', () => {
  let server;

  afterEach(async () => {
    if (server) {
      await closeServer(server);
      server = undefined;
    }
  });

  it('bounds a hung health response with a per-request timeout', async () => {
    server = http.createServer((_req, _res) => {
      // Keep the socket open without sending headers.
    });
    const port = await listen(server);
    const started = Date.now();

    await expect(waitForHttpHealth(`http://127.0.0.1:${port}`, {}, {
      timeoutMs: 250,
      intervalMs: 10,
      fetchTimeoutMs: 50,
    })).rejects.toThrow(/did not become healthy/);

    expect(Date.now() - started).toBeLessThan(2_000);
  });
});
