import { createHash } from 'node:crypto';

export function canonicalWorkspaceLabelID(value) {
  const raw = String(value ?? '');
  const cleaned = raw
    .replace(/[^A-Za-z0-9_.-]/g, '-')
    .replace(/-{2,}/g, '-')
    .replace(/^[^A-Za-z0-9]+|[^A-Za-z0-9]+$/g, '') || 'unknown';
  if (cleaned === raw && cleaned.length <= 63) return cleaned;

  const hash = createHash('sha256').update(raw).digest('hex').slice(0, 10);
  const prefix = cleaned.slice(0, Math.max(1, 63 - hash.length - 1)).replace(/[-_.]+$/g, '') || 'workspace';
  return `${prefix}-${hash}`;
}
