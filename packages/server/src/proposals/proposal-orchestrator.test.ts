import type { SecurityPrincipal } from '@inkeep/open-knowledge-core';
import { describe, expect, test, vi } from 'vitest';
import {
  __proposalOrchestratorTestExports,
  createProposalOrchestrator,
  ProposalOrchestratorError,
  ProposalRuntimeDescriptorSchema,
  type ProposalRuntimeProvisioner,
} from './proposal-orchestrator.ts';
import type { ProposalWorkspace, ProposalWorkspaceService } from './proposal-workspace.ts';

const principal: SecurityPrincipal = {
  id: 'human:giorgio',
  kind: 'human',
  issuer: 'https://issuer.example.com/',
  subject: 'giorgio',
  capabilities: ['knowledge.read', 'knowledge.propose'],
};

const workspace: ProposalWorkspace = {
  record: {
    version: 1,
    proposalId: 'proposal-1',
    principalId: principal.id,
    branch: 'ok/proposals/opaque/proposal-1',
    worktreePath: '/trusted/repo/.ok/worktrees/proposals/opaque/proposal-1',
    createdAt: '2026-08-05T12:00:00.000Z',
    updatedAt: '2026-08-05T12:01:00.000Z',
  },
  runtimeScope: {
    kind: 'proposal',
    proposalId: 'proposal-1',
    principalId: principal.id,
    branch: 'ok/proposals/opaque/proposal-1',
  },
  created: true,
};

const readyRuntime = {
  runtimeId: 'runtime:proposal-1',
  state: 'ready' as const,
  updatedAt: '2026-08-05T12:02:00.000Z',
  browserUrl: 'https://knowledge.example.com/proposals/proposal-1',
  mcpUrl: 'https://knowledge.example.com/proposals/proposal-1/mcp',
};

function setup(
  options: {
    found?: ProposalWorkspace | null;
    ensureResult?: unknown;
    inspectResult?: unknown;
    ensureFailure?: Error;
    stopFailure?: Error;
  } = {},
) {
  const workspaces: ProposalWorkspaceService = {
    createOrResume: vi.fn(async () => workspace),
    get: vi.fn(() => (options.found === undefined ? workspace : options.found)),
    abandon: vi.fn(async () => undefined),
  };
  const provisioner: ProposalRuntimeProvisioner = {
    ensureRunning: vi.fn(async () => {
      if (options.ensureFailure) throw options.ensureFailure;
      return (options.ensureResult ?? readyRuntime) as typeof readyRuntime;
    }),
    inspect: vi.fn(
      async () =>
        (options.inspectResult === undefined ? readyRuntime : options.inspectResult) as
          | typeof readyRuntime
          | null,
    ),
    stop: vi.fn(async () => {
      if (options.stopFailure) throw options.stopFailure;
    }),
  };
  return {
    orchestrator: createProposalOrchestrator({ workspaces, provisioner }),
    workspaces,
    provisioner,
  };
}

describe('ProposalRuntimeDescriptorSchema', () => {
  test('accepts bounded credential-free HTTP(S) endpoints', () => {
    expect(ProposalRuntimeDescriptorSchema.parse(readyRuntime)).toEqual(readyRuntime);
    expect(
      ProposalRuntimeDescriptorSchema.parse({
        runtimeId: 'runtime-2',
        state: 'starting',
        updatedAt: readyRuntime.updatedAt,
        browserUrl: 'http://127.0.0.1:3000/proposal',
        message: 'Starting',
      }).state,
    ).toBe('starting');
    expect(
      ProposalRuntimeDescriptorSchema.parse({
        runtimeId: 'runtime-3',
        state: 'ready',
        updatedAt: readyRuntime.updatedAt,
        mcpUrl: 'https://knowledge.example.com/proposals/proposal-3/mcp',
      }).state,
    ).toBe('ready');
  });

  test.each([
    [
      'ready without a connection URL',
      { ...readyRuntime, browserUrl: undefined, mcpUrl: undefined },
    ],
    ['credentials in a URL', { ...readyRuntime, browserUrl: 'https://user@example.com/path' }],
    ['password in a URL', { ...readyRuntime, browserUrl: 'https://user:secret@example.com/path' }],
    ['query data in a URL', { ...readyRuntime, browserUrl: 'https://example.com/path?token=x' }],
    ['URL fragments', { ...readyRuntime, browserUrl: 'https://example.com/path#token' }],
    ['non-HTTP endpoints', { ...readyRuntime, browserUrl: 'file:///tmp/runtime' }],
    ['unsafe runtime ids', { ...readyRuntime, runtimeId: '../runtime' }],
  ])('rejects %s', (_label, candidate) => {
    expect(ProposalRuntimeDescriptorSchema.safeParse(candidate).success).toBe(false);
  });
});

describe('createProposalOrchestrator', () => {
  test('requires a valid principal with proposal capability', async () => {
    const { orchestrator, workspaces } = setup();
    await expect(
      orchestrator.startOrResume({ ...principal, id: 'invalid' } as SecurityPrincipal),
    ).rejects.toMatchObject({ code: 'invalid-principal' });
    await expect(
      orchestrator.startOrResume({ ...principal, capabilities: ['knowledge.read'] }),
    ).rejects.toMatchObject({ code: 'proposal-capability-required' });
    expect(workspaces.createOrResume).not.toHaveBeenCalled();
  });

  test('starts a validated workspace without exposing its filesystem path', async () => {
    const { orchestrator, workspaces, provisioner } = setup();
    const session = await orchestrator.startOrResume(principal, { proposalId: 'proposal-1' });
    expect(workspaces.createOrResume).toHaveBeenCalledWith(principal, {
      proposalId: 'proposal-1',
    });
    expect(provisioner.ensureRunning).toHaveBeenCalledWith({
      runtimeKey: expect.stringMatching(/^[a-f0-9]{64}$/),
      runtimeScope: workspace.runtimeScope,
      projectDir: workspace.record.worktreePath,
    });
    expect(session).toEqual({
      proposalId: 'proposal-1',
      branch: workspace.record.branch,
      createdAt: workspace.record.createdAt,
      updatedAt: workspace.record.updatedAt,
      runtime: readyRuntime,
    });
    expect(JSON.stringify(session)).not.toContain(workspace.record.worktreePath);
  });

  test('uses generated workspace ids when none are supplied', async () => {
    const { orchestrator, workspaces } = setup();
    await orchestrator.startOrResume(principal);
    expect(workspaces.createOrResume).toHaveBeenCalledWith(principal, {});
  });

  test('coalesces concurrent starts per proposal and permits later reconciliation', async () => {
    let resolveRuntime!: (runtime: typeof readyRuntime) => void;
    const deferred = new Promise<typeof readyRuntime>((resolve) => {
      resolveRuntime = resolve;
    });
    const { orchestrator, provisioner, workspaces } = setup();
    vi.mocked(provisioner.ensureRunning).mockImplementation(async () => await deferred);

    const first = orchestrator.startOrResume(principal, { proposalId: 'proposal-1' });
    const second = orchestrator.startOrResume(principal, { proposalId: 'proposal-1' });
    await vi.waitFor(() => expect(provisioner.ensureRunning).toHaveBeenCalledTimes(1));
    resolveRuntime(readyRuntime);
    await expect(Promise.all([first, second])).resolves.toHaveLength(2);
    expect(workspaces.createOrResume).toHaveBeenCalledTimes(1);

    await orchestrator.startOrResume(principal, { proposalId: 'proposal-1' });
    expect(provisioner.ensureRunning).toHaveBeenCalledTimes(2);
  });

  test('does not serialize unrelated proposal runtimes', async () => {
    let resolveFirst!: (runtime: typeof readyRuntime) => void;
    const firstRuntime = new Promise<typeof readyRuntime>((resolve) => {
      resolveFirst = resolve;
    });
    const secondWorkspace: ProposalWorkspace = {
      ...workspace,
      record: {
        ...workspace.record,
        proposalId: 'proposal-2',
        branch: 'ok/proposals/opaque/proposal-2',
        worktreePath: '/trusted/repo/.ok/worktrees/proposals/opaque/proposal-2',
      },
      runtimeScope: {
        ...workspace.runtimeScope,
        proposalId: 'proposal-2',
        branch: 'ok/proposals/opaque/proposal-2',
      },
    };
    const { orchestrator, workspaces, provisioner } = setup();
    vi.mocked(workspaces.createOrResume).mockImplementation(async (_principal, options) =>
      options?.proposalId === 'proposal-2' ? secondWorkspace : workspace,
    );
    vi.mocked(provisioner.ensureRunning).mockImplementation(async (input) =>
      input.runtimeScope.proposalId === 'proposal-1'
        ? await firstRuntime
        : { ...readyRuntime, runtimeId: 'runtime:proposal-2' },
    );

    const first = orchestrator.startOrResume(principal, { proposalId: 'proposal-1' });
    const second = orchestrator.startOrResume(principal, { proposalId: 'proposal-2' });
    await expect(second).resolves.toMatchObject({ proposalId: 'proposal-2' });
    expect(provisioner.ensureRunning).toHaveBeenCalledTimes(2);
    resolveFirst(readyRuntime);
    await expect(first).resolves.toMatchObject({ proposalId: 'proposal-1' });
  });

  test('preserves the proposal for retry when provisioning fails', async () => {
    const failure = new Error('adapter details');
    const { orchestrator, workspaces } = setup({ ensureFailure: failure });
    await expect(orchestrator.startOrResume(principal)).rejects.toMatchObject({
      code: 'runtime-provisioning-failed',
      cause: failure,
    });
    expect(workspaces.abandon).not.toHaveBeenCalled();
  });

  test('fails closed on an invalid provisioner response', async () => {
    const { orchestrator, workspaces } = setup({
      ensureResult: { ...readyRuntime, browserUrl: 'https://example.com/?token=secret' },
    });
    await expect(orchestrator.startOrResume(principal)).rejects.toMatchObject({
      code: 'invalid-runtime-descriptor',
    });
    expect(workspaces.abandon).not.toHaveBeenCalled();
  });

  test('inspects existing sessions and reports absent workspace or runtime state', async () => {
    const active = setup();
    await expect(active.orchestrator.get(principal, 'proposal-1')).resolves.toMatchObject({
      proposalId: 'proposal-1',
      runtime: readyRuntime,
    });
    expect(active.provisioner.inspect).toHaveBeenCalledWith({
      runtimeKey: expect.stringMatching(/^[a-f0-9]{64}$/),
      runtimeScope: workspace.runtimeScope,
    });

    const missingWorkspace = setup({ found: null });
    await expect(missingWorkspace.orchestrator.get(principal, 'proposal-1')).resolves.toBeNull();
    expect(missingWorkspace.provisioner.inspect).not.toHaveBeenCalled();

    const missingRuntime = setup({ inspectResult: null });
    await expect(missingRuntime.orchestrator.get(principal, 'proposal-1')).resolves.toBeNull();

    const invalidRuntime = setup({ inspectResult: { ...readyRuntime, runtimeId: 'bad id' } });
    await expect(invalidRuntime.orchestrator.get(principal, 'proposal-1')).rejects.toMatchObject({
      code: 'invalid-runtime-descriptor',
    });
  });

  test('waits for an in-flight lifecycle operation before inspecting', async () => {
    let resolveRuntime!: (runtime: typeof readyRuntime) => void;
    const deferred = new Promise<typeof readyRuntime>((resolve) => {
      resolveRuntime = resolve;
    });
    const { orchestrator, provisioner } = setup();
    vi.mocked(provisioner.ensureRunning).mockImplementation(async () => await deferred);

    const start = orchestrator.startOrResume(principal, { proposalId: 'proposal-1' });
    await vi.waitFor(() => expect(provisioner.ensureRunning).toHaveBeenCalledTimes(1));
    const inspect = orchestrator.get(principal, 'proposal-1');
    expect(provisioner.inspect).not.toHaveBeenCalled();
    resolveRuntime(readyRuntime);
    await start;
    await expect(inspect).resolves.toMatchObject({ proposalId: 'proposal-1' });
    expect(provisioner.inspect).toHaveBeenCalledTimes(1);
  });

  test('stops a runtime before abandoning the worktree and is idempotent when absent', async () => {
    const active = setup();
    const order: string[] = [];
    vi.mocked(active.provisioner.stop).mockImplementation(async () => {
      order.push('stop');
    });
    vi.mocked(active.workspaces.abandon).mockImplementation(async () => {
      order.push('abandon');
    });
    await active.orchestrator.abandon(principal, 'proposal-1');
    expect(order).toEqual(['stop', 'abandon']);

    const absent = setup({ found: null });
    await absent.orchestrator.abandon(principal, 'proposal-1');
    expect(absent.provisioner.stop).not.toHaveBeenCalled();
    expect(absent.workspaces.abandon).not.toHaveBeenCalled();
  });

  test('waits for an in-flight start before stopping and abandoning that proposal', async () => {
    let resolveRuntime!: (runtime: typeof readyRuntime) => void;
    const deferred = new Promise<typeof readyRuntime>((resolve) => {
      resolveRuntime = resolve;
    });
    const { orchestrator, workspaces, provisioner } = setup();
    vi.mocked(provisioner.ensureRunning).mockImplementation(async () => await deferred);

    const start = orchestrator.startOrResume(principal, { proposalId: 'proposal-1' });
    await vi.waitFor(() => expect(provisioner.ensureRunning).toHaveBeenCalledTimes(1));
    const abandon = orchestrator.abandon(principal, 'proposal-1');
    expect(provisioner.stop).not.toHaveBeenCalled();
    resolveRuntime(readyRuntime);
    await start;
    await abandon;
    expect(provisioner.stop).toHaveBeenCalledTimes(1);
    expect(workspaces.abandon).toHaveBeenCalledTimes(1);
  });

  test('does not remove the workspace when runtime shutdown fails', async () => {
    const failure = new Error('runtime still active');
    const { orchestrator, workspaces } = setup({ stopFailure: failure });
    await expect(orchestrator.abandon(principal, 'proposal-1')).rejects.toBe(failure);
    expect(workspaces.abandon).not.toHaveBeenCalled();
  });

  test('derives stable opaque runtime keys from both owner and proposal', () => {
    const first = __proposalOrchestratorTestExports.runtimeKeyFor(workspace.runtimeScope);
    expect(
      __proposalOrchestratorTestExports.runtimeKeyFor({
        ...workspace.runtimeScope,
        proposalId: 'proposal-2',
      }),
    ).not.toBe(first);
    expect(
      __proposalOrchestratorTestExports.runtimeKeyFor({
        ...workspace.runtimeScope,
        principalId: 'human:other',
      }),
    ).not.toBe(first);
    expect(
      __proposalOrchestratorTestExports.runtimeKeyForIdentity(
        workspace.runtimeScope.principalId,
        workspace.runtimeScope.proposalId,
      ),
    ).toBe(first);
  });

  test('exposes typed orchestration errors without infrastructure details in messages', () => {
    expect(
      new ProposalOrchestratorError('runtime-provisioning-failed', 'Safe message', {
        cause: new Error('private detail'),
      }),
    ).toMatchObject({
      name: 'ProposalOrchestratorError',
      code: 'runtime-provisioning-failed',
      message: 'Safe message',
    });
  });
});
