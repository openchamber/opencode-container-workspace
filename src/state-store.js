import { constants } from 'node:fs';
import { chmod, mkdir, open, readFile, rename, rm, stat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { StateStoreError } from './errors.js';
import { protectDirectoryForCurrentUser } from './windows-acl.js';

const LOCK_STALE_MS = 5 * 60_000;
const LOCK_WAIT_MS = 30_000;

export function stateRoot() {
  return process.env.OPENCHAMBER_WORKSPACE_STATE_DIR
    ? String(process.env.OPENCHAMBER_WORKSPACE_STATE_DIR)
    : join(homedir(), '.config', 'openchamber', 'workspace-plugin-v1');
}

export function workspaceStateDirectory(providerResourceID) {
  assertKey(providerResourceID);
  return join(stateRoot(), 'workspaces', providerResourceID);
}

export async function withWorkspaceLock(providerResourceID, callback, options = {}) {
  assertKey(providerResourceID);
  const root = stateRoot();
  await secureDirectory(root);
  const locks = join(root, 'locks');
  await secureDirectory(locks);
  const lock = join(locks, `${providerResourceID}.lock`);
  const deadline = Date.now() + (options.waitMs ?? LOCK_WAIT_MS);
  while (true) {
    try {
      await mkdir(lock, { mode: 0o700 });
      await atomicWrite(join(lock, 'owner.json'), JSON.stringify({ pid: process.pid, createdAt: new Date().toISOString() }));
      break;
    } catch (error) {
      if (error?.code !== 'EEXIST') throw new StateStoreError(`Unable to acquire workspace lock: ${providerResourceID}`, { cause: error });
      if (await staleLock(lock, options.staleMs ?? LOCK_STALE_MS)) {
        await rm(lock, { recursive: true, force: true });
        continue;
      }
      if (Date.now() >= deadline) throw new StateStoreError(`Workspace operation is already in progress: ${providerResourceID}`, { code: 'WORKSPACE_LOCKED' });
      await delay(50 + Math.floor(Math.random() * 100));
    }
  }
  try {
    return await callback();
  } finally {
    await rm(lock, { recursive: true, force: true });
  }
}

export async function readWorkspaceState(providerResourceID) {
  const path = join(workspaceStateDirectory(providerResourceID), 'state.json');
  let raw;
  try {
    raw = await readFile(path, 'utf8');
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw new StateStoreError(`Unable to read workspace state: ${providerResourceID}`, { cause: error });
  }
  try {
    const value = JSON.parse(raw);
    if (!value || typeof value !== 'object' || Array.isArray(value) || value.providerResourceID !== providerResourceID) throw new Error('invalid state shape');
    return value;
  } catch (error) {
    throw new StateStoreError(`Workspace state is corrupt: ${providerResourceID}`, { code: 'WORKSPACE_STATE_CORRUPT', cause: error });
  }
}

export async function writeWorkspaceState(providerResourceID, state) {
  const directory = workspaceStateDirectory(providerResourceID);
  await secureDirectory(directory);
  await atomicWrite(join(directory, 'state.json'), `${JSON.stringify(state, null, 2)}\n`);
}

export async function writeWorkspaceSecret(providerResourceID, name, value) {
  assertKey(name);
  const directory = join(workspaceStateDirectory(providerResourceID), 'secrets');
  await secureDirectory(directory);
  const path = join(directory, name);
  await atomicWrite(path, String(value));
  return path;
}

export async function readWorkspaceSecret(providerResourceID, name) {
  assertKey(name);
  try {
    return await readFile(join(workspaceStateDirectory(providerResourceID), 'secrets', name), 'utf8');
  } catch (error) {
    if (error?.code === 'ENOENT') throw new StateStoreError(`Workspace secret is missing: ${name}`, { code: 'WORKSPACE_SECRET_MISSING' });
    throw new StateStoreError(`Unable to read workspace secret: ${name}`, { cause: error });
  }
}

export async function deleteWorkspaceSecret(providerResourceID, name) {
  assertKey(name);
  await rm(join(workspaceStateDirectory(providerResourceID), 'secrets', name), { force: true });
}

export async function deleteWorkspaceState(providerResourceID) {
  await rm(workspaceStateDirectory(providerResourceID), { recursive: true, force: true });
}

export async function atomicWrite(path, content) {
  await secureDirectory(dirname(path));
  const temporary = `${path}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
  let handle;
  try {
    handle = await open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
    await handle.writeFile(content);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporary, path);
    const directory = await open(dirname(path), constants.O_RDONLY);
    await directory.sync().catch(() => undefined);
    await directory.close();
  } catch (error) {
    await handle?.close().catch(() => undefined);
    await rm(temporary, { force: true }).catch(() => undefined);
    throw new StateStoreError(`Atomic state write failed: ${path}`, { cause: error });
  }
}

async function secureDirectory(path) {
  const root = stateRoot();
  await mkdir(root, { recursive: true, mode: 0o700 });
  await chmod(root, 0o700);
  // Windows accepts both of the above and honours neither. The root carries an
  // inheritable ACL instead, so every directory and file created below it is restricted
  // without a call of its own.
  await protectDirectoryForCurrentUser(root);
  await mkdir(path, { recursive: true, mode: 0o700 });
  await chmod(path, 0o700);
}

async function staleLock(path, staleMs) {
  try {
    const value = await stat(path);
    if (Date.now() - value.mtimeMs <= staleMs) return false;
    const owner = JSON.parse(await readFile(join(path, 'owner.json'), 'utf8'));
    if (Number.isInteger(owner.pid) && owner.pid > 0) {
      try {
        process.kill(owner.pid, 0);
        return false;
      } catch (error) {
        if (error?.code === 'EPERM') return false;
      }
    }
    return true;
  } catch (error) {
    return error?.code === 'ENOENT' || Date.now() - (await stat(path).catch(() => ({ mtimeMs: Date.now() }))).mtimeMs > staleMs;
  }
}

function assertKey(value) {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$/.test(String(value))) throw new StateStoreError('Invalid state key');
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
