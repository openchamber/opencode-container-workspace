import { beforeEach, describe, expect, it, vi } from 'vitest';

const processMocks = vi.hoisted(() => ({
  run: vi.fn(),
  spawnBackground: vi.fn(),
}));

const authMocks = vi.hoisted(() => ({
  createWorkspaceToken: vi.fn(async (id) => ({ tokenRef: `token-${id}`, token: `secret-${id}` })),
  deleteWorkspaceToken: vi.fn(async () => undefined),
  getWorkspaceToken: vi.fn(async () => 'runtime-token'),
}));

vi.mock('../process.js', async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual,
    run: processMocks.run,
    spawnBackground: processMocks.spawnBackground,
  };
});

vi.mock('../auth.js', async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, ...authMocks };
});

const { readPolicy } = await import('../policy.js');
const { createKubernetesProvider } = await import('./kubernetes.js');

function readKubernetesTestPolicy() {
  return readPolicy({
    defaultImage: 'workspace-image:1.0.0',
    requirePinnedImage: false,
    egress: {
      httpProxy: 'http://10.0.0.10:3128',
      proxyCIDR: '10.0.0.10/32',
      dnsCIDRs: ['10.0.0.53/32'],
      noProxy: '127.0.0.1,localhost',
    },
  });
}

describe('kubernetes workspace provider identity reconstruction', () => {
  beforeEach(() => {
    processMocks.run.mockReset();
    processMocks.run.mockResolvedValue({ stdout: '', stderr: '' });
    authMocks.createWorkspaceToken.mockClear();
  });

  it.each(['ws:1/abc', '_ws', 'ws_', '.'])('reconstructs listed workspace ID %s with the same token ref and Secret after restart', async (workspaceID) => {
    const policy = readKubernetesTestPolicy();
    const provider = createKubernetesProvider({ policy, sourceDirectory: '/source' });
    const info = provider.configure({ id: workspaceID, projectID: 'project:1' });
    expect(info.extra.labels['openchamber.io/workspace-id']).toMatch(/^[A-Za-z0-9]([A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?$/);
    processMocks.run
      .mockResolvedValueOnce({ stdout: 'Client Version: v1.36.2\n', stderr: '' })
      .mockResolvedValueOnce({
      stdout: JSON.stringify({
        items: [{
          metadata: {
            name: info.extra.runtime.deployment,
            labels: info.extra.labels,
          },
        }],
      }),
      stderr: '',
    });

    const listed = await provider.list({ instance: { project: { id: 'project:1' } } });

    expect(listed).toHaveLength(1);
    expect(listed[0].extra.auth.tokenRef).toBe(info.extra.auth.tokenRef);
    expect(listed[0].extra.runtime.deployment).toBe(info.extra.runtime.deployment);
    expect(listed[0].extra.runtime.service).toBe(info.extra.runtime.service);
    expect(listed[0].extra.runtime.secret).toBe(info.extra.runtime.secret);
    expect(listed[0].extra.runtime.networkPolicy).toBe(info.extra.runtime.networkPolicy);
    expect(listed[0].extra.storage.pvc).toBe(info.extra.storage.pvc);
  });

  it('applies a default-deny NetworkPolicy for new workspaces by default', async () => {
    const policy = readKubernetesTestPolicy();
    const provider = createKubernetesProvider({ policy, sourceDirectory: '/source' });
    const info = provider.configure({ id: 'ws_1', projectID: 'project:1' });
    processMocks.run.mockImplementation(async (_binary, args, options = {}) => {
      if (args.includes('can-i')) return { stdout: 'yes\n', stderr: '' };
      if (args.includes('apply')) return { stdout: '', stderr: '' };
      if (args.includes('rollout')) throw new Error('stop after manifest apply');
      if (args.includes('get')) throw new Error('not found');
      return { stdout: '', stderr: '' };
    });

    await expect(provider.create(info, { OPENCODE_AUTH_CONTENT: '{}' })).rejects.toThrow(/stop after manifest apply/);

    const applyCall = processMocks.run.mock.calls.find(([, args]) => args.includes('apply'));
    const manifest = JSON.parse(applyCall?.[2]?.input ?? '{}');
    const networkPolicy = manifest.items.find((item) => item.kind === 'NetworkPolicy');
    expect(networkPolicy).toMatchObject({
      apiVersion: 'networking.k8s.io/v1',
      metadata: { name: info.extra.runtime.networkPolicy, namespace: info.extra.runtime.namespace },
      spec: {
        podSelector: { matchLabels: { 'openchamber.io/workspace-id': info.extra.labels['openchamber.io/workspace-id'] } },
        policyTypes: ['Ingress', 'Egress'],
        ingress: [],
        egress: [
          {
            to: [{ ipBlock: { cidr: '10.0.0.53/32' } }],
            ports: [{ protocol: 'UDP', port: 53 }, { protocol: 'TCP', port: 53 }],
          },
          {
            to: [{ ipBlock: { cidr: '10.0.0.10/32' } }],
            ports: [{ protocol: 'TCP', port: 3128 }],
          },
        ],
      },
    });
  });

  it('rejects default-deny creation without explicit proxy and DNS egress', async () => {
    const policy = readPolicy({ defaultImage: 'workspace-image:1.0.0', requirePinnedImage: false });
    const provider = createKubernetesProvider({ policy, sourceDirectory: '/source' });
    const info = provider.configure({ id: 'ws_1', projectID: 'project:1' });

    await expect(provider.create(info, { OPENCODE_AUTH_CONTENT: '{}' })).rejects.toThrow(/require.*egress/i);
    expect(processMocks.run).not.toHaveBeenCalled();
  });
});
