import { describe, expect, it } from 'vitest';
import { run } from './process.js';

describe('structured process runner', () => {
  it('redacts marked values from command arguments and process output', async () => {
    const secret = 'super-secret-token';
    const error = await run(process.execPath, ['-e', `process.stderr.write('${secret}');process.exit(2)`, secret], { sensitiveArgs: [2], sensitiveValues: [secret] }).catch((value) => value);
    expect(error.message).not.toContain(secret);
    expect(error.stderr).toBe('[REDACTED]');
    expect(error.message).toContain('[REDACTED]');
  });

  it('bounds captured output and reports truncation', async () => {
    const error = await run(process.execPath, ['-e', "process.stderr.write('x'.repeat(10000));process.exit(1)"], { maxOutputBytes: 128 }).catch((value) => value);
    expect(error.stderr).toHaveLength(128);
    expect(error.truncated).toBe(true);
  });

  it('suppresses source or artifact output in error diagnostics', async () => {
    const error = await run(process.execPath, ['-e', "process.stdout.write('private source');process.exit(2)"], { sensitiveOutput: true, sensitiveArgs: [1] }).catch((value) => value);
    expect(error.message).not.toContain('private source');
    expect(error.stdout).toBe('[REDACTED OUTPUT]');
  });

  it('distinguishes timeout failures', async () => {
    const error = await run(process.execPath, ['-e', 'setTimeout(()=>{}, 10000)'], { timeoutMs: 20 }).catch((value) => value);
    expect(error.kind).toBe('timeout');
    expect(error.message).toMatch(/timed out/);
  });
});
