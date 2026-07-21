import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
import { homedir } from 'node:os';
import { canonicalWorkspaceLabelID } from './label-id.js';

const STATE_DIR = join(homedir(), '.config', 'openchamber', 'workspace-plugin');
const TOKEN_FILE = join(STATE_DIR, 'tokens.json');

export const AUTH_HEADER = 'x-openchamber-workspace-token';

export function createTokenRef(workspaceID) {
  const hash = createHash('sha256').update(canonicalWorkspaceLabelID(workspaceID)).digest('hex').slice(0, 24);
  return `workspace-${hash}`;
}

export async function createWorkspaceToken(workspaceID) {
  const token = randomBytes(32).toString('base64url');
  const tokenRef = createTokenRef(workspaceID);
  const tokens = await readTokens();
  tokens[tokenRef] = token;
  await writeTokens(tokens);
  return { tokenRef, token };
}

export async function getWorkspaceToken(tokenRef) {
  const tokens = await readTokens();
  const token = tokens[tokenRef];
  if (!token) throw new Error(`Workspace auth token is missing for ${tokenRef}`);
  return token;
}

export async function deleteWorkspaceToken(tokenRef) {
  const tokens = await readTokens();
  delete tokens[tokenRef];
  await writeTokens(tokens);
}

async function readTokens() {
  try {
    const raw = await readFile(TOKEN_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

async function writeTokens(tokens) {
  await mkdir(STATE_DIR, { recursive: true, mode: 0o700 });
  await writeFile(TOKEN_FILE, JSON.stringify(tokens, null, 2), { mode: 0o600 });
}
