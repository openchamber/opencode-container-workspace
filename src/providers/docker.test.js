import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ProcessError } from '../errors.js';

const processMocks = vi.hoisted(() => ({ commandExists: vi.fn(() => true), run: vi.fn(), runJson: vi.fn() }));
vi.mock('../process.js', async (importOriginal) => ({ ...await importOriginal(), ...processMocks }));
const { readPolicy } = await import('../policy.js');
const { createDockerProvider } = await import('./docker.js');

const dockerExitError = (stderr, options = {}) => new ProcessError(`docker failed with ${options.exitCode ?? 1}: ${stderr}`, {
  kind: options.kind ?? 'exit',
  exitCode: options.exitCode ?? 1,
  stderr,
  truncated: options.truncated ?? false,
});

describe('Docker provider security and transactions', () => {
  let stateDirectory;
  beforeEach(async () => {
    stateDirectory = await mkdtemp(join(tmpdir(), 'workspace-docker-test-'));
    process.env.OPENCHAMBER_WORKSPACE_STATE_DIR = stateDirectory;
    processMocks.commandExists.mockReturnValue(true);
    processMocks.run.mockReset().mockResolvedValue({ stdout: '', stderr: '' });
    processMocks.runJson.mockReset().mockRejectedValue(dockerExitError('Error: No such object: workspace-resource'));
  });
  afterEach(async () => {
    delete process.env.OPENCHAMBER_WORKSPACE_STATE_DIR;
    await rm(stateDirectory, { recursive: true, force: true });
  });

  function configured(sourceDirectory = '/source') {
    const policy = readPolicy({ defaultImage: 'workspace-image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', egress: { mode: 'external', proxyUrl: 'http://proxy:3128' }, credentials: { modelAuth: 'explicit-opencode-auth-content' } });
    const provider = createDockerProvider({ policy, sourceDirectory });
    return { policy, provider, info: provider.configure({ id: 'control-plane-id', projectID: 'project-id' }) };
  }

  function configuredWithProxy(proxyUrl, sourceDirectory) {
    const policy = readPolicy({ defaultImage: 'workspace-image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', egress: { mode: 'external', proxyUrl } });
    const provider = createDockerProvider({ policy, sourceDirectory });
    return { provider, info: provider.configure({ id: 'control-plane-id', projectID: 'project-id' }) };
  }

  it('uses opaque provider identity and canonical per-workspace resources without trusted labels in metadata', () => {
    const { info } = configured();
    expect(info.extra).toMatchObject({ version: 1, provider: 'docker', controlPlaneWorkspaceID: 'control-plane-id', projectID: 'project-id', runtimeLayoutVersion: 1 });
    expect(info.extra.providerResourceID).toMatch(/^ws-[a-f0-9]{32}$/);
    expect(info.extra.resourceRefs.network).toContain(info.extra.providerResourceID);
    expect(info.extra.resourceRefs.baselineVolume).toMatch(/baseline$/);
    expect(info.extra).not.toHaveProperty('labels');
    expect(info.extra).not.toHaveProperty('policy');
  });

  it('rejects metadata resource-name tampering before provider commands', async () => {
    const { provider, info } = configured();
    const tampered = { ...info, extra: { ...info.extra, resourceRefs: { ...info.extra.resourceRefs, runtime: 'foreign' } } };
    await expect(provider.target(tampered)).rejects.toThrow(/not canonical/);
    expect(processMocks.runJson).not.toHaveBeenCalled();
  });

  it('rolls back only resources created by the failed operation and never injects broad auth as environment', async () => {
    const sourceDirectory = join(stateDirectory, 'source');
    await mkdir(sourceDirectory);
    const { provider, info } = configured(sourceDirectory);
    processMocks.run.mockImplementation(async (_binary, args) => {
      if (args[0] === 'volume' && args[1] === 'create' && args.at(-1).endsWith('-baseline')) throw new Error('baseline create failed');
      return { stdout: '', stderr: '' };
    });
    await expect(provider.create(info, { OPENCODE_AUTH_CONTENT: '{"provider":"secret"}' })).rejects.toThrow(/baseline create failed/);
    const commands = processMocks.run.mock.calls.map(([, args]) => args);
    expect(commands).toContainEqual(expect.arrayContaining(['network', 'rm', info.extra.resourceRefs.network]));
    expect(commands).toContainEqual(expect.arrayContaining(['volume', 'rm', info.extra.resourceRefs.mutableVolume]));
    expect(commands).not.toContainEqual(expect.arrayContaining(['rm', '-f', info.extra.resourceRefs.runtime]));
    expect(JSON.stringify(commands)).not.toContain('provider\\":\\"secret');
    expect(JSON.stringify(commands)).not.toContain('OPENCODE_AUTH_CONTENT=');
  });

  it('treats Docker 20.10 missing-network diagnostics as authoritative absence', async () => {
    const sourceDirectory = join(stateDirectory, 'source');
    await mkdir(sourceDirectory);
    const { provider, info } = configured(sourceDirectory);
    processMocks.runJson.mockImplementation(async (_binary, args) => {
      if (args[0] === 'network') throw dockerExitError(`Error: No such network: ${args.at(-1)}`);
      if (args[0] === 'volume') throw dockerExitError(`Error: No such volume: ${args.at(-1)}`);
      throw dockerExitError(`Error: No such object: ${args.at(-1)}`);
    });
    processMocks.run.mockImplementation(async (_binary, args) => {
      if (args[0] === 'network' && args[1] === 'create') throw new Error('network creation reached');
      return { stdout: '', stderr: '' };
    });

    await expect(provider.create(info)).rejects.toThrow('network creation reached');
    expect(processMocks.run).toHaveBeenCalledWith('docker', expect.arrayContaining(['network', 'create', info.extra.resourceRefs.network]), expect.any(Object));
  });

  it('treats current Docker missing-volume diagnostics as idempotent cleanup', async () => {
    const { provider, info } = configured();
    processMocks.run.mockImplementation(async (_binary, args) => {
      if (args[0] === 'volume' && args[1] === 'rm') {
        throw dockerExitError(`Error response from daemon: get ${args.at(-1)}: no such volume`);
      }
      return { stdout: '', stderr: '' };
    });

    await expect(provider.remove(info)).resolves.toMatchObject({ ok: true, remainingResources: [] });
  });

  it.each([
    ['plain errors', new Error('network not found')],
    ['timeouts', dockerExitError('network not found', { kind: 'timeout', exitCode: null })],
    ['unrelated daemon failures', dockerExitError('permission denied')],
    ['truncated diagnostics', dockerExitError('Error: No such network: workspace-resource', { truncated: true })],
  ])('does not treat %s as authoritative Docker absence', async (_label, failure) => {
    const sourceDirectory = join(stateDirectory, 'source');
    await mkdir(sourceDirectory);
    const { provider, info } = configured(sourceDirectory);
    processMocks.runJson.mockRejectedValue(failure);

    await expect(provider.create(info)).rejects.toBe(failure);
    expect(processMocks.run.mock.calls.some(([, args]) => args[0] === 'network' && args[1] === 'create')).toBe(false);
  });

  it('runs short-lived seed helpers as the unprivileged runtime user', async () => {
    const sourceDirectory = join(stateDirectory, 'source');
    await mkdir(sourceDirectory);
    const { provider, info } = configured(sourceDirectory);
    processMocks.run.mockImplementation(async (_binary, args) => {
      if (args[0] === 'run' && args.includes('-d') && args.includes(info.extra.resourceRefs.runtime)) throw new Error('runtime create failed');
      return { stdout: '', stderr: '' };
    });

    await expect(provider.create(info)).rejects.toThrow(/runtime create failed/);

    const helperCommands = processMocks.run.mock.calls
      .map(([, args]) => args)
      .filter((args) => args[0] === 'run' && args.includes('--network') && args.includes('none'));
    expect(helperCommands.length).toBeGreaterThanOrEqual(2);
    for (const command of helperCommands) {
      expect(command).toEqual(expect.arrayContaining(['--user', '1000:1000', '--network', 'none', '--cap-drop', 'ALL']));
      expect(command).not.toContain('--cap-add');
    }
    const secretCommand = helperCommands.find((command) => command.some((arg) => arg.startsWith(`${info.extra.resourceRefs.secretVolume}:`)));
    expect(secretCommand).toContain('-i');
    expect(secretCommand).not.toContainEqual(expect.stringContaining('/input'));
    const runtimeCommand = processMocks.run.mock.calls.map(([, args]) => args).find((args) => args.includes(info.extra.resourceRefs.runtime) && args.includes('-d'));
    expect(runtimeCommand).toEqual(expect.arrayContaining(['--read-only', '--tmpfs', '/tmp:rw,exec,nosuid,size=256m']));
    expect(runtimeCommand.some((arg) => arg.startsWith('OPENCODE_WORKSPACE_ID='))).toBe(false);
    expect(processMocks.runJson.mock.calls.every(([, args]) => args[0] !== 'inspect' || args[1] !== 'inspect')).toBe(true);
  });

  it('uses verified TLS for HTTPS external proxies and preserves idle upgraded streams', async () => {
    const sourceDirectory = join(stateDirectory, 'source');
    await mkdir(sourceDirectory);
    const { provider, info } = configuredWithProxy('https://proxy.example.com:8443', sourceDirectory);

    await expect(provider.create(info)).rejects.toThrow(/No such object/);
    const gateway = processMocks.run.mock.calls.map(([, args]) => args).find((args) => args.includes(info.extra.resourceRefs.gateway) && args.includes('OPENCHAMBER_PROXY_TLS=true'));
    expect(gateway).toEqual(expect.arrayContaining([
      'OPENCHAMBER_PROXY_HOST=proxy.example.com', 'OPENCHAMBER_PROXY_PORT=8443',
      'OPENCHAMBER_PROXY_TLS=true', 'OPENCHAMBER_PROXY_SERVERNAME=proxy.example.com',
    ]));
    const bridge = gateway.at(-1);
    expect(bridge).toContain("tls.connect({host,port,servername:net.isIP(servername)?undefined:servername}");
    expect(bridge).toContain("u.once(secure?'secureConnect':'connect',()=>u.setTimeout(0))");
    const access = processMocks.run.mock.calls.map(([, args]) => args).find((args) => args.includes(info.extra.resourceRefs.access));
    expect(access.at(-1)).toContain('upstream.setTimeout(0)');
  });
});
