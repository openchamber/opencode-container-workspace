import { HealthCheckError } from './errors.js';

export async function waitForHttpHealth(url, headers = {}, options = {}) {
  const timeoutMs = options.timeoutMs ?? 60_000;
  const intervalMs = options.intervalMs ?? 1_000;
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(new URL('/global/health', url), { headers });
      if (response.ok) return true;
      lastError = new Error(`Health endpoint returned ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  throw new HealthCheckError(`Workspace runtime did not become healthy: ${lastError?.message ?? 'timeout'}`, {
    cause: lastError,
  });
}
