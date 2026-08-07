import { afterEach, describe, expect, it } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseAccountSid, parseGrantedPrincipals, protectDirectoryForCurrentUser, resetWindowsAclCache } from './windows-acl.js';
import { run } from './process.js';

const icacls = `${process.env.SystemRoot || 'C:\\Windows'}\\System32\\icacls.exe`;

describe('windows state protection', () => {
  const created = [];

  /** The principal lines of an access list, joined so a test can match across them. */
  async function granted(path) {
    const { stdout } = await run(icacls, [path]);
    return stdout.split(/\r?\n/).filter((line) => line.includes(':(')).join('\n');
  }

  /** A directory anyone on the machine can read, so removing that grant is observable. */
  async function openDirectory() {
    const directory = await mkdtemp(join(tmpdir(), 'workspace-acl-test-'));
    created.push(directory);
    await run(icacls, [directory, '/grant', '*S-1-1-0:(OI)(CI)F', '/q']);
    return directory;
  }
  afterEach(async () => {
    resetWindowsAclCache();
    await Promise.all(created.splice(0).map((path) => rm(path, { recursive: true, force: true })));
  });

  it('reads every principal out of a list, including one whose name has a space', () => {
    const path = 'C:\\Users\\BOHDAN~1\\AppData\\Local\\Temp\\acl-probe';
    const output = [
      `${path} Everyone:(OI)(CI)(F)`,
      '                                             NT AUTHORITY\\SYSTEM:(I)(OI)(CI)(F)',
      '                                             BUILTIN\\Administrators:(I)(OI)(CI)(F)',
      '                                             DESKTOP-CP9J2I4\\Bohdan Triapitsyn:(I)(OI)(CI)(F)',
      '',
      'Successfully processed 1 files; Failed processing 0 files',
    ].join('\r\n');
    expect(parseGrantedPrincipals(output, path)).toEqual([
      'Everyone',
      'NT AUTHORITY\\SYSTEM',
      'BUILTIN\\Administrators',
      'DESKTOP-CP9J2I4\\Bohdan Triapitsyn',
    ]);
  });

  it('reads the account identifier out of what whoami prints', () => {
    expect(parseAccountSid('"CORP\\\\yulia","S-1-5-21-1004336348-1177238915-682003330-512"\r\n'))
      .toBe('S-1-5-21-1004336348-1177238915-682003330-512');
    expect(parseAccountSid('')).toBeNull();
  });

  it('does nothing where POSIX modes already restrict the store', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'workspace-acl-test-'));
    created.push(directory);
    expect(await protectDirectoryForCurrentUser(directory, { platform: 'linux' })).toBe(false);
  });

  it.runIf(process.platform === 'win32')('removes a grant that was there before it, not only inherited ones', async () => {
    const directory = await openDirectory();
    // %TEMP% is already private on a normal profile, so a directory made there cannot
    // show whether anything was actually taken away. This one is opened to Everyone
    // first — an explicit entry, which `/grant:r` alone would leave untouched.
    expect(await granted(directory)).toMatch(/Everyone/i);

    expect(await protectDirectoryForCurrentUser(directory)).toBe(true);

    expect(await granted(directory)).not.toMatch(/Everyone/i);
    expect(await granted(directory)).toContain(process.env.USERNAME);
  });

  it.runIf(process.platform === 'win32')('passes the restriction down to files created afterwards', async () => {
    const directory = await openDirectory();
    await protectDirectoryForCurrentUser(directory);
    const secret = join(directory, 'endpoint-token');
    await writeFile(secret, 'secret');

    expect(await granted(secret)).not.toMatch(/Everyone/i);
    expect(await granted(secret)).toContain(process.env.USERNAME);
  });

  it.runIf(process.platform === 'win32')('asks the operating system once per root, not once per write', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'workspace-acl-test-'));
    created.push(directory);
    expect(await protectDirectoryForCurrentUser(directory)).toBe(true);
    expect(await protectDirectoryForCurrentUser(directory)).toBe(false);
  });
});
