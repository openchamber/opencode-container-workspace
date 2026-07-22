import { randomBytes } from 'node:crypto';
import { deleteWorkspaceSecret, readWorkspaceSecret, withWorkspaceLock, writeWorkspaceSecret } from './state-store.js';

export const AUTH_HEADER = 'x-openchamber-workspace-token';
export const AUTH_SECRET_NAME = 'endpoint-token';
export const MODEL_AUTH_SECRET_NAME = 'model-auth.json';

export function createTokenRef(providerResourceID) {
  return `${providerResourceID}/${AUTH_SECRET_NAME}`;
}

export async function createWorkspaceSecrets(providerResourceID, env = {}) {
  let suppliedModelAuth;
  if (env.OPENCODE_AUTH_CONTENT !== undefined && env.OPENCODE_AUTH_CONTENT !== '') suppliedModelAuth = normalizeSuppliedModelAuth(env.OPENCODE_AUTH_CONTENT);
  const token = await readWorkspaceSecret(providerResourceID, AUTH_SECRET_NAME).catch((error) => {
    if (error?.code === 'WORKSPACE_SECRET_MISSING') return randomBytes(32).toString('base64url');
    throw error;
  });
  const tokenPath = await writeWorkspaceSecret(providerResourceID, AUTH_SECRET_NAME, token);
  let modelAuthPath;
  const existingModelAuth = await readWorkspaceSecret(providerResourceID, MODEL_AUTH_SECRET_NAME).catch((error) => {
    if (error?.code === 'WORKSPACE_SECRET_MISSING') return undefined;
    throw error;
  });
  const modelAuth = existingModelAuth ?? suppliedModelAuth;
  if (modelAuth !== undefined) modelAuthPath = await writeWorkspaceSecret(providerResourceID, MODEL_AUTH_SECRET_NAME, modelAuth);
  return { token, tokenPath, modelAuth, modelAuthPath, tokenRef: createTokenRef(providerResourceID) };
}

function normalizeSuppliedModelAuth(value) {
  try {
    const parsed = JSON.parse(value);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('expected an object');
    return JSON.stringify(parsed);
  } catch (cause) {
    throw new TypeError(`OPENCODE_AUTH_CONTENT must be valid JSON object content: ${cause.message}`);
  }
}

export function selectGrantedCredentials(policy, env = {}) {
  if (policy.credentials.modelAuth !== 'explicit-opencode-auth-content') return {};
  return env.OPENCODE_AUTH_CONTENT === undefined ? {} : { OPENCODE_AUTH_CONTENT: env.OPENCODE_AUTH_CONTENT };
}

export async function getWorkspaceToken(tokenRef) {
  const [providerResourceID, name, extra] = String(tokenRef).split('/');
  if (!providerResourceID || name !== AUTH_SECRET_NAME || extra !== undefined) throw new TypeError('Invalid workspace token reference');
  return readWorkspaceSecret(providerResourceID, AUTH_SECRET_NAME);
}

export async function rotateWorkspaceCredentials(providerResourceID, request, updateProvider) {
  return withWorkspaceLock(providerResourceID, async () => {
  const previousToken = await readWorkspaceSecret(providerResourceID, AUTH_SECRET_NAME);
  const previousModelAuth = await readWorkspaceSecret(providerResourceID, MODEL_AUTH_SECRET_NAME).catch((error) => {
    if (error?.code === 'WORKSPACE_SECRET_MISSING') return undefined;
    throw error;
  });
  const nextToken = request.rotateEndpointToken === false ? previousToken : randomBytes(32).toString('base64url');
  const nextModelAuth = request.modelAuth === undefined ? previousModelAuth : request.modelAuth === null ? undefined : normalizeModelAuth(request.modelAuth);
  try {
    await updateProvider({ token: nextToken, modelAuth: nextModelAuth });
    await writeWorkspaceSecret(providerResourceID, AUTH_SECRET_NAME, nextToken);
    if (nextModelAuth === undefined) await deleteWorkspaceSecret(providerResourceID, MODEL_AUTH_SECRET_NAME);
    else await writeWorkspaceSecret(providerResourceID, MODEL_AUTH_SECRET_NAME, nextModelAuth);
  } catch (cause) {
    const rollbackErrors = [];
    try {
      await updateProvider({ token: previousToken, modelAuth: previousModelAuth });
    } catch (rollbackError) {
      rollbackErrors.push(rollbackError);
    }
    try {
      await writeWorkspaceSecret(providerResourceID, AUTH_SECRET_NAME, previousToken);
      if (previousModelAuth === undefined) await deleteWorkspaceSecret(providerResourceID, MODEL_AUTH_SECRET_NAME);
      else await writeWorkspaceSecret(providerResourceID, MODEL_AUTH_SECRET_NAME, previousModelAuth);
    } catch (rollbackError) {
      rollbackErrors.push(rollbackError);
    }
    if (rollbackErrors.length > 0) throw new AggregateError([cause, ...rollbackErrors], 'Credential rotation failed and rollback was incomplete', { cause });
    throw cause;
  }
  return { rotatedEndpointToken: nextToken !== previousToken, modelAuth: nextModelAuth === undefined ? 'revoked' : 'configured' };
  });
}

function normalizeModelAuth(value) {
  const parsed = typeof value === 'string' ? JSON.parse(value) : value;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new TypeError('Model authentication grant must be a JSON object');
  return JSON.stringify(parsed);
}
