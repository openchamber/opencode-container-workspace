import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { StateStoreError } from './errors.js';

/**
 * Setting an access list is an operating-system primitive, not a provider command, so it
 * runs through `child_process` rather than the shared runner. The runner carries argument
 * redaction and provider attribution that mean nothing here, and — the reason that
 * matters — provider tests replace it wholesale, which would leave the state store unable
 * to write a file in any suite that mocks a container CLI.
 */
const exec = promisify(execFile);

/**
 * The state store declares `0o700` directories and `0o600` files, and Windows implements
 * neither — `chmod` is close to a no-op there and every file reports `0o666`. Under the
 * default data directory the store is nonetheless private, because it inherits the
 * profile's permissions; move it to a second drive, a shared folder, or anywhere else an
 * operator points `OPENCHAMBER_WORKSPACE_STATE_DIR` and it inherits that location's
 * instead. What the store holds is container endpoint tokens, so the protection has to be
 * stated rather than inherited.
 *
 * Windows states it with an ACL, which Node cannot set, so this shells out to `icacls`
 * once per state root: inheritance is removed and full control granted to this account,
 * SYSTEM, and Administrators — the last two by SID, because their names are localised and
 * `Administrators` does not exist on a Ukrainian or German install.
 */

const SYSTEM_SID = '*S-1-5-18';
const ADMINISTRATORS_SID = '*S-1-5-32-544';

const protectedRoots = new Set();
let accountSid;

/**
 * Both of these are named by absolute path rather than looked up on PATH. Git for Windows
 * ships a POSIX `whoami` that takes no `/user`, and it usually comes first — the same way
 * its `tar` shadows the system one and misreads `C:\…` as a remote host. Whichever tool
 * answers should not depend on what else happens to be installed.
 */
function system32(binary) {
  return `${process.env.SystemRoot || 'C:\\Windows'}\\System32\\${binary}`;
}

export function resetWindowsAclCache() {
  protectedRoots.clear();
  accountSid = undefined;
}

/** Parses `whoami /user /fo csv /nh`, which prints `"DOMAIN\user","S-1-5-21-…"`. */
export function parseAccountSid(output) {
  const match = /S-1-[0-9-]+/.exec(String(output ?? ''));
  return match ? match[0] : null;
}

async function currentAccountSid() {
  if (accountSid) return accountSid;
  let result;
  try {
    result = await exec(system32('whoami.exe'), ['/user', '/fo', 'csv', '/nh'], { timeout: 15_000, windowsHide: true });
  } catch (error) {
    throw new StateStoreError('Unable to identify the current Windows account, so workspace state cannot be restricted to it.', { cause: error });
  }
  const sid = parseAccountSid(result.stdout);
  if (!sid) throw new StateStoreError('Windows reported no security identifier for the current account, so workspace state cannot be restricted to it.');
  accountSid = sid;
  return sid;
}

/**
 * Lists the principals holding an entry on a path. `icacls` puts the path and the first
 * entry on one line and indents the rest:
 *
 *     C:\…\workspaces Everyone:(OI)(CI)(F)
 *                     NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
 *                     DESKTOP-CP9J2I4\Bohdan Triapitsyn:(I)(OI)(CI)(F)
 *
 * The path has to come off first: it contains the drive's colon, and a principal may
 * contain spaces, so there is no separator that tells them apart on that first line.
 */
export function parseGrantedPrincipals(output, path) {
  const principals = [];
  const prefix = String(path ?? '');
  for (const raw of String(output ?? '').split(/\r?\n/)) {
    const line = prefix && raw.toLowerCase().startsWith(prefix.toLowerCase()) ? raw.slice(prefix.length) : raw;
    const match = /^\s*(\S.*?):\([A-Z]+\)/.exec(line);
    if (match) principals.push(match[1].trim());
  }
  return principals;
}

/**
 * Restricts a directory and everything created beneath it to this account. Children
 * inherit the entries, so this runs once per root rather than once per write.
 *
 * Neither switch does the whole job on its own. `/inheritance:r` drops what the parent
 * contributed, and `/grant:r` replaces the permissions of the principals it names — but
 * an entry someone added explicitly for a third party is touched by neither and simply
 * stays. So the list is emptied first and rebuilt second, rather than granting over
 * whatever was already there; the owner may always rewrite its own list, which is why the
 * directory does not lock this process out in between.
 */
export async function protectDirectoryForCurrentUser(path, { platform = process.platform } = {}) {
  if (platform !== 'win32') return false;
  if (protectedRoots.has(path)) return false;
  const sid = await currentAccountSid();
  const icacls = system32('icacls.exe');
  try {
    const options = { timeout: 30_000, windowsHide: true };
    await exec(icacls, [path, '/inheritance:r', '/q'], options);
    const { stdout } = await exec(icacls, [path], options);
    for (const principal of parseGrantedPrincipals(stdout, path)) {
      await exec(icacls, [path, '/remove:g', principal, '/q'], options);
    }
    await exec(icacls, [
      path,
      '/grant:r', `*${sid}:(OI)(CI)F`,
      '/grant:r', `${SYSTEM_SID}:(OI)(CI)F`,
      '/grant:r', `${ADMINISTRATORS_SID}:(OI)(CI)F`,
      '/q',
    ], options);
  } catch (error) {
    throw new StateStoreError(`Unable to restrict workspace state to the current account: ${path}`, { cause: error });
  }
  protectedRoots.add(path);
  return true;
}
