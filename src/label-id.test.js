import { describe, expect, it } from 'vitest';
import { canonicalWorkspaceLabelID } from './label-id.js';

describe('canonicalWorkspaceLabelID', () => {
  it('preserves Kubernetes-valid IDs', () => {
    expect(canonicalWorkspaceLabelID('ws_1')).toBe('ws_1');
  });

  it.each(['_ws', 'ws_', '.', '-ws', 'ws-', '.ws', 'ws.'])('normalizes boundary punctuation for %s', (id) => {
    const canonical = canonicalWorkspaceLabelID(id);

    expect(canonical).toMatch(/^[A-Za-z0-9]([A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?$/);
    expect(canonical).not.toBe(id);
  });
});
