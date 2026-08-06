import { spawn, spawnSync } from 'node:child_process';
import { createWriteStream } from 'node:fs';
import { canonicalWorkspaceLabelID } from './label-id.js';
import { ProcessError } from './errors.js';

const DEFAULT_TIMEOUT_MS = 120_000;
const DEFAULT_MAX_OUTPUT_BYTES = 1024 * 1024;

export function commandExists(binary) {
  const result = spawnSync(binary, ['--version'], { stdio: 'ignore', windowsHide: true, timeout: 15_000 });
  return result.status === 0;
}

export function run(binary, args, options = {}) {
  if (typeof binary !== 'string' || !binary || !Array.isArray(args) || args.some((arg) => typeof arg !== 'string')) {
    return Promise.reject(new TypeError('Process runner requires an executable and string argument array'));
  }
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxOutputBytes = options.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;
  const sensitiveValues = [...(options.sensitiveValues ?? [])].filter(Boolean).map(String);
  const display = formatCommand(binary, args, options.sensitiveArgs ?? [], sensitiveValues);
  return new Promise((resolve, reject) => {
    const child = spawn(binary, args, {
      cwd: options.cwd,
      env: options.env ? { ...process.env, ...options.env } : process.env,
      stdio: [options.input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    let truncated = false;
    let settled = false;
    const append = (current, chunk) => {
      const incoming = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      if (current.length >= maxOutputBytes) {
        truncated = true;
        return current;
      }
      if (current.length + incoming.length > maxOutputBytes) truncated = true;
      return Buffer.concat([current, incoming.subarray(0, maxOutputBytes - current.length)]);
    };
    const finishError = (kind, message, details = {}) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      options.signal?.removeEventListener('abort', abort);
      const out = options.sensitiveOutput && stdout.length > 0 ? '[REDACTED OUTPUT]' : redact(decode(stdout), sensitiveValues);
      const err = options.sensitiveOutput && stderr.length > 0 ? '[REDACTED OUTPUT]' : redact(decode(stderr), sensitiveValues);
      reject(new ProcessError(`${display} ${message}${err || out ? `: ${err || out}` : ''}`.trim(), {
        kind,
        exitCode: details.exitCode,
        signal: details.signal,
        stdout: out,
        stderr: err,
        truncated,
        cause: details.cause,
      }));
    };
    const terminate = () => {
      if (process.platform === 'win32' && child.pid) {
        spawn('taskkill', ['/pid', String(child.pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true });
      } else {
        child.kill('SIGKILL');
      }
    };
    const abort = () => {
      terminate();
      finishError('abort', 'was aborted');
    };
    const timer = setTimeout(() => {
      terminate();
      finishError('timeout', `timed out after ${timeoutMs}ms`);
    }, timeoutMs);
    options.signal?.addEventListener('abort', abort, { once: true });
    if (options.signal?.aborted) abort();

    child.stdout?.on('data', (chunk) => { stdout = append(stdout, chunk); });
    child.stderr?.on('data', (chunk) => { stderr = append(stderr, chunk); });
    child.on('error', (error) => finishError('spawn', 'could not be started', { cause: error }));
    if (options.input !== undefined) {
      if (typeof options.input?.pipe === 'function') options.input.pipe(child.stdin);
      else child.stdin?.end(options.input);
    }
    child.on('close', (code, signal) => {
      if (settled) return;
      if (code !== 0 && !(options.allowedExitCodes ?? []).includes(code)) {
        finishError(signal ? 'signal' : 'exit', `failed with ${signal ?? code}`, { exitCode: code, signal });
        return;
      }
      settled = true;
      clearTimeout(timer);
      options.signal?.removeEventListener('abort', abort);
      resolve({ stdout: decode(stdout), stderr: decode(stderr), truncated });
    });
  });
}

/**
 * Runs a command and writes its stdout to a file, so the destination never has to be
 * passed to the command as an argument.
 *
 * That matters on Windows: GNU tar reads `C:\path` as a remote `host:path` and fails
 * with "Cannot connect to C", while the bsdtar shipped in System32 accepts it. Which one
 * runs is decided by PATH order, so the same command works or fails depending on whether
 * Git for Windows appears first — and Git for Windows very often does. Handing the path
 * over stdout removes the question instead of detecting the flavour, which would have to
 * be re-detected for every tool that takes a path.
 */
export function runToFile(binary, args, destinationPath, options = {}) {
  if (typeof binary !== 'string' || !binary || !Array.isArray(args) || args.some((arg) => typeof arg !== 'string')) {
    return Promise.reject(new TypeError('Process runner requires an executable and string argument array'));
  }
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const display = formatCommand(binary, args, options.sensitiveArgs ?? [], []);
  return new Promise((resolve, reject) => {
    const output = createWriteStream(destinationPath);
    const child = spawn(binary, args, {
      cwd: options.cwd,
      env: options.env ? { ...process.env, ...options.env } : process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    let stderr = '';
    let settled = false;
    const fail = (kind, message, details = {}) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      output.destroy();
      reject(new ProcessError(`${display} ${message}${stderr ? `: ${stderr.trim()}` : ''}`.trim(), { kind, stderr, ...details }));
    };
    const timer = setTimeout(() => {
      if (process.platform === 'win32' && child.pid) spawn('taskkill', ['/pid', String(child.pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true });
      else child.kill('SIGKILL');
      fail('timeout', `timed out after ${timeoutMs}ms`);
    }, timeoutMs);

    child.stderr.on('data', (chunk) => { if (stderr.length < 64 * 1024) stderr += String(chunk); });
    child.on('error', (error) => fail('spawn', `could not start: ${error.message}`));
    output.on('error', (error) => fail('exit', `could not write output: ${error.message}`));
    child.stdout.pipe(output);
    child.on('close', (code, signal) => {
      if (settled) return;
      if (code !== 0) {
        fail('exit', `failed with ${code ?? signal}`, { exitCode: code, signal });
        return;
      }
      // Resolve only once the file is closed, so a caller may read it immediately.
      output.end(() => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve({ stderr });
      });
    });
  });
}

export function spawnBackground(binary, args, options = {}) {
  return spawn(binary, args, {
    cwd: options.cwd,
    env: options.env ? { ...process.env, ...options.env } : process.env,
    stdio: options.stdio ?? 'ignore',
    detached: options.detached ?? false,
    windowsHide: true,
  });
}

export async function runJson(binary, args, options = {}) {
  const { stdout, truncated } = await run(binary, args, options);
  if (truncated) throw new ProcessError(`${binary} returned JSON larger than the configured output limit`, { kind: 'decode', truncated: true });
  if (!stdout.trim()) return null;
  try {
    return JSON.parse(stdout);
  } catch (cause) {
    throw new ProcessError(`${binary} returned malformed JSON`, { kind: 'decode', cause });
  }
}

export function redact(value, sensitiveValues = []) {
  let result = String(value ?? '');
  for (const secret of sensitiveValues.filter(Boolean).sort((a, b) => b.length - a.length)) result = result.split(secret).join('[REDACTED]');
  return result
    .replace(/(authorization\s*[:=]\s*)(?:bearer\s+)?[^\s,;]+/gi, '$1[REDACTED]')
    .replace(/(OPENCODE_AUTH_CONTENT=)[^\s]+/g, '$1[REDACTED]')
    .replace(/(x-openchamber-workspace-token\s*[:=]\s*)[^\s,;]+/gi, '$1[REDACTED]');
}

export function sanitizeLabelValue(value) {
  return canonicalWorkspaceLabelID(value);
}

function formatCommand(binary, args, sensitiveArgs, sensitiveValues) {
  const hidden = new Set(sensitiveArgs);
  return [binary, ...args.map((arg, index) => hidden.has(index) ? '[REDACTED]' : redact(arg, sensitiveValues))].join(' ');
}

function decode(buffer) {
  return buffer.toString('utf8').replace(/\uFFFD/g, '?');
}
