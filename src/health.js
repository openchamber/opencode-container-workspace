import { HealthCheckError } from './errors.js';

export async function waitForHttpHealth(url, headers = {}, options = {}) {
  const timeoutMs = options.timeoutMs ?? 60_000;
  const intervalMs = options.intervalMs ?? 1_000;
  const fetchTimeoutMs = options.fetchTimeoutMs ?? 5_000;
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(new URL('/global/health', url), { headers, signal: AbortSignal.timeout(fetchTimeoutMs) });
      if (response.ok) return true;
      const body = await response.text().catch(() => '');
      lastError = new Error(`Health endpoint returned ${response.status}${body ? `: ${body.slice(0, 500)}` : ''}`);
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, Math.min(intervalMs, Math.max(0, deadline - Date.now()))));
  }
  throw new HealthCheckError(`Workspace runtime did not become healthy: ${lastError?.message ?? 'timeout'}`, {
    cause: lastError,
  });
}
