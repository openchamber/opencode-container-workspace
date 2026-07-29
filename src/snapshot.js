import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { chmod, lstat, mkdtemp, readFile, readdir, readlink, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { run } from './process.js';

const DEFAULT_LIMITS = Object.freeze({ maxEntries: 100_000, maxBytes: 2 * 1024 ** 3, maxFileBytes: 256 * 1024 ** 2 });
const RESERVED_ROOTS = new Set(['.openchamber', '.openchamber-runtime']);
const EXCLUDED_ROOTS = new Set(['.git']);

export async function createSourceSnapshot(sourceDirectory, options = {}) {
  const root = await realpath(sourceDirectory);
  const rootStat = await lstat(root);
  if (!rootStat.isDirectory()) throw new Error('Workspace source must be a directory');
  const limits = { ...DEFAULT_LIMITS, ...options.limits };
  const before = await scanSourceTree(root, limits);
  await options.beforeArchive?.();
  const temporaryDirectory = await mkdtemp(join(options.temporaryRoot ?? tmpdir(), 'openchamber-source-'));
  await chmod(temporaryDirectory, 0o700);
  const archivePath = join(temporaryDirectory, 'source.tar');
  try {
    await run('tar', ['-cf', archivePath, '--exclude', './.git', '.'], { cwd: root, env: { COPYFILE_DISABLE: '1' }, timeoutMs: options.timeoutMs ?? 300_000, maxOutputBytes: 64 * 1024 });
    const after = await scanSourceTree(root, limits);
    if (JSON.stringify(before.entries) !== JSON.stringify(after.entries)) throw new Error('Workspace source changed while the immutable snapshot was being created');
    const generation = createHash('sha256').update(JSON.stringify(before.entries.map(({ mtimeNs, ...entry }) => entry))).digest('hex');
    return {
      archivePath,
      generation,
      entries: before.entries,
      totalBytes: before.totalBytes,
      createReadStream: () => createReadStream(archivePath),
      dispose: () => rm(temporaryDirectory, { recursive: true, force: true }),
    };
  } catch (error) {
    await rm(temporaryDirectory, { recursive: true, force: true });
    throw error;
  }
}

export async function scanSourceTree(root, limits = DEFAULT_LIMITS) {
  const entries = [];
  let totalBytes = 0;
  async function visit(directory, relativeDirectory = '') {
    const names = (await readdir(directory)).sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
    for (const name of names) {
      if (!relativeDirectory && EXCLUDED_ROOTS.has(name)) continue;
      if (!relativeDirectory && RESERVED_ROOTS.has(name)) throw new Error(`Workspace source contains reserved control path: ${name}`);
      if (name.includes('\0')) throw new Error('Workspace source path contains NUL');
      const relativePath = relativeDirectory ? `${relativeDirectory}/${name}` : name;
      if (relativePath.startsWith('/') || relativePath.split('/').includes('..')) throw new Error(`Unsafe workspace source path: ${relativePath}`);
      const absolutePath = join(directory, name);
      const statBefore = await lstat(absolutePath, { bigint: true });
      if (++entries.length > limits.maxEntries) throw new Error(`Workspace source exceeds ${limits.maxEntries} entries`);
      const base = { path: relativePath, mode: Number(statBefore.mode & 0o7777n), mtimeNs: String(statBefore.mtimeNs) };
      if (statBefore.isDirectory()) {
        entries[entries.length - 1] = { ...base, type: 'directory' };
        await visit(absolutePath, relativePath);
      } else if (statBefore.isSymbolicLink()) {
        const target = await readlink(absolutePath);
        if (isAbsolute(target) || escapesRoot(root, dirname(absolutePath), target)) throw new Error(`Workspace source symlink escapes the project: ${relativePath}`);
        entries[entries.length - 1] = { ...base, type: 'symlink', target, hash: createHash('sha256').update(target).digest('hex') };
      } else if (statBefore.isFile()) {
        const size = Number(statBefore.size);
        if (size > limits.maxFileBytes) throw new Error(`Workspace source file exceeds ${limits.maxFileBytes} bytes: ${relativePath}`);
        totalBytes += size;
        if (totalBytes > limits.maxBytes) throw new Error(`Workspace source exceeds ${limits.maxBytes} bytes`);
        const content = await readFile(absolutePath);
        const statAfter = await lstat(absolutePath, { bigint: true });
        if (statBefore.size !== statAfter.size || statBefore.mtimeNs !== statAfter.mtimeNs || statBefore.ino !== statAfter.ino) throw new Error(`Workspace source changed while reading: ${relativePath}`);
        entries[entries.length - 1] = { ...base, type: 'file', size, hash: createHash('sha256').update(content).digest('hex') };
      } else {
        throw new Error(`Workspace source contains unsupported special file: ${relativePath}`);
      }
    }
  }
  await visit(root);
  return { entries, totalBytes };
}

function escapesRoot(root, parent, target) {
  const resolved = resolve(parent, target);
  const path = relative(root, resolved);
  return path === '..' || path.startsWith(`..${sep}`) || isAbsolute(path);
}
