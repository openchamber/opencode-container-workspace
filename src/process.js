import { canonicalWorkspaceLabelID } from './label-id.js';
import { spawn, spawnSync } from 'node:child_process';

const DEFAULT_TIMEOUT_MS = 120_000;

export function commandExists(binary) {
  const result = spawnSync(binary, ['--version'], { stdio: 'ignore', windowsHide: true });
  return result.status === 0;
}

export function run(binary, args, options = {}) {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  return new Promise((resolve, reject) => {
    const child = spawn(binary, args, {
      cwd: options.cwd,
      env: options.env ? { ...process.env, ...options.env } : process.env,
      stdio: [options.input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
    let stdout = '';
    let stderr = '';
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill('SIGKILL');
      reject(new Error(`${binary} ${args.join(' ')} timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    child.stdout?.on('data', (chunk) => {
      stdout += chunk.toString('utf8');
    });
    child.stderr?.on('data', (chunk) => {
      stderr += chunk.toString('utf8');
    });
    child.on('error', (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error);
    });
    if (options.input !== undefined) {
      child.stdin?.end(options.input);
    }
    child.on('close', (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (code === 0) {
        resolve({ stdout, stderr });
        return;
      }
      const failure = new Error(`${binary} ${args.join(' ')} failed with ${signal ?? code}: ${stderr || stdout}`.trim());
      failure.code = code;
      failure.signal = signal;
      failure.stdout = stdout;
      failure.stderr = stderr;
      reject(failure);
    });
  });
}

export function spawnBackground(binary, args, options = {}) {
  const child = spawn(binary, args, {
    cwd: options.cwd,
    env: options.env ? { ...process.env, ...options.env } : process.env,
    stdio: options.stdio ?? 'ignore',
    detached: options.detached ?? false,
    windowsHide: true,
  });
  return child;
}

export async function runJson(binary, args, options = {}) {
  const { stdout } = await run(binary, args, options);
  if (!stdout.trim()) return null;
  return JSON.parse(stdout);
}

export function sanitizeLabelValue(value) {
  return canonicalWorkspaceLabelID(value);
}
