import { execFileSync } from 'node:child_process';
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import type { BridgeWorktreeEntry, SecurityPrincipal } from '@inkeep/open-knowledge-core';
import { describe, expect, test } from 'vitest';
import {
  __proposalWorkspaceTestExports,
  createProposalWorkspaceService,
  type ProposalWorkspaceGit,
} from './proposal-workspace.ts';

const principal: SecurityPrincipal = {
  id: 'human:auth0-owner',
  kind: 'human',
  issuer: 'https://issuer.example/',
  subject: 'auth0|owner',
  capabilities: ['knowledge.read', 'knowledge.propose'],
};

class FakeGit implements ProposalWorkspaceGit {
  worktrees: BridgeWorktreeEntry[] = [];
  branches = new Set<string>();
  dirty = false;
  createCalls: Parameters<ProposalWorkspaceGit['createWorktree']>[0][] = [];
  removeCalls: string[] = [];
  deleteCalls: string[] = [];
  createFailure: Error | null = null;
  deleteFailure: Error | null = null;
  removeFailure: Error | null = null;

  async listWorktrees() {
    return this.worktrees;
  }
  async branchExists(branch: string) {
    return this.branches.has(branch);
  }
  async createWorktree(input: Parameters<ProposalWorkspaceGit['createWorktree']>[0]) {
    if (this.createFailure) throw this.createFailure;
    this.createCalls.push(input);
    this.branches.add(input.branch);
    this.worktrees.push({
      path: input.worktreePath,
      branch: input.branch,
      headSha: 'abc',
      locked: false,
      prunable: false,
    });
  }
  async isDirty() {
    return this.dirty;
  }
  async removeWorktree(worktreePath: string) {
    this.removeCalls.push(worktreePath);
    if (this.removeFailure) throw this.removeFailure;
    this.worktrees = this.worktrees.filter((entry) => entry.path !== worktreePath);
  }
  async deleteBranch(branch: string) {
    this.deleteCalls.push(branch);
    if (this.deleteFailure) throw this.deleteFailure;
    this.branches.delete(branch);
  }
}

function tempRepo(): string {
  return realpathSync(mkdtempSync(join(tmpdir(), 'ok-proposal-')));
}

function service(repoRoot: string, git: FakeGit, overrides = {}) {
  return createProposalWorkspaceService({
    repoRoot,
    git,
    createId: () => 'proposal-1',
    now: () => new Date('2026-08-05T12:00:00.000Z'),
    ...overrides,
  });
}

describe('createProposalWorkspaceService', () => {
  test('validates configuration, principals, and proposal ids', async () => {
    expect(() => createProposalWorkspaceService({ repoRoot: 'relative' })).toThrow(
      'Proposal repository root must be absolute.',
    );
    expect(() =>
      createProposalWorkspaceService({ repoRoot: tempRepo(), publishedBranch: '../main' }),
    ).toThrow('Published branch is invalid.');

    const repoRoot = tempRepo();
    const workspaceService = service(repoRoot, new FakeGit());
    await expect(
      workspaceService.createOrResume({ ...principal, id: 'invalid' }),
    ).rejects.toMatchObject({ code: 'invalid-principal' });
    await expect(
      workspaceService.createOrResume(principal, { proposalId: '../escape' }),
    ).rejects.toMatchObject({ code: 'invalid-proposal-id' });
    expect(() => workspaceService.get(principal, '../escape')).toThrow('Proposal id is invalid.');
    expect(() =>
      __proposalWorkspaceTestExports.assertContained(repoRoot, join(repoRoot, '..', 'escape')),
    ).toThrow('Proposal runtime path escaped its repository boundary.');
  });

  test('creates, persists, and resumes one principal-scoped workspace', async () => {
    const repoRoot = tempRepo();
    const git = new FakeGit();
    const workspaceService = service(repoRoot, git);

    const created = await workspaceService.createOrResume(principal);
    expect(created.created).toBe(true);
    expect(created.runtimeScope).toEqual({
      kind: 'proposal',
      proposalId: 'proposal-1',
      principalId: principal.id,
      branch: created.record.branch,
    });
    expect(created.record.branch).toMatch(/^ok\/proposals\/[a-f0-9]{20}\/proposal-1$/);
    expect(git.createCalls).toEqual([
      expect.objectContaining({
        branch: created.record.branch,
        publishedBranch: 'main',
        createBranch: true,
      }),
    ]);
    const persisted = JSON.parse(
      readFileSync(
        __proposalWorkspaceTestExports.buildRecordPaths(repoRoot, principal.id, 'proposal-1')
          .statePath,
        'utf8',
      ),
    );
    expect(persisted).toMatchObject({ principalId: principal.id, version: 1 });

    const resumed = await workspaceService.createOrResume(principal);
    expect(resumed).toEqual({ ...created, created: false });
    expect(workspaceService.get(principal, 'proposal-1')).toEqual(resumed);
    expect(git.createCalls).toHaveLength(1);
  });

  test('serializes concurrent create requests for the same proposal', async () => {
    const git = new FakeGit();
    const workspaceService = service(tempRepo(), git);
    const [first, second] = await Promise.all([
      workspaceService.createOrResume(principal),
      workspaceService.createOrResume(principal),
    ]);
    expect([first.created, second.created].sort()).toEqual([false, true]);
    expect(git.createCalls).toHaveLength(1);
  });

  test('recovers an unregistered existing worktree and an existing branch', async () => {
    const repoRoot = tempRepo();
    const git = new FakeGit();
    const paths = __proposalWorkspaceTestExports.buildRecordPaths(
      repoRoot,
      principal.id,
      'proposal-1',
    );
    git.branches.add(paths.branch);
    git.worktrees.push({
      path: paths.worktreePath,
      branch: paths.branch,
      headSha: 'abc',
      locked: false,
      prunable: false,
    });
    const recovered = await service(repoRoot, git).createOrResume(principal);
    expect(recovered.created).toBe(false);
    expect(git.createCalls).toHaveLength(0);

    const secondRoot = tempRepo();
    const secondGit = new FakeGit();
    const secondPaths = __proposalWorkspaceTestExports.buildRecordPaths(
      secondRoot,
      principal.id,
      'proposal-1',
    );
    secondGit.branches.add(secondPaths.branch);
    await service(secondRoot, secondGit).createOrResume(principal);
    expect(secondGit.createCalls[0]?.createBranch).toBe(false);
  });

  test('recreates a missing registered worktree but refuses a missing branch', async () => {
    const repoRoot = tempRepo();
    const git = new FakeGit();
    const workspaceService = service(repoRoot, git);
    await workspaceService.createOrResume(principal);
    git.worktrees = [];
    const resumed = await workspaceService.createOrResume(principal);
    expect(resumed.created).toBe(true);
    expect(git.createCalls.at(-1)?.createBranch).toBe(false);

    const missingRoot = tempRepo();
    const missingGit = new FakeGit();
    const missingService = service(missingRoot, missingGit);
    await missingService.createOrResume(principal);
    missingGit.worktrees = [];
    missingGit.branches.clear();
    await expect(missingService.createOrResume(principal)).rejects.toThrow(
      'Proposal state references a missing Git branch.',
    );

    const unsafeRoot = tempRepo();
    const unsafeGit = new FakeGit();
    const unsafeService = service(unsafeRoot, unsafeGit);
    await unsafeService.createOrResume(principal);
    unsafeGit.worktrees = [{ ...unsafeGit.worktrees[0], path: join(unsafeRoot, 'unsafe') }];
    await expect(unsafeService.createOrResume(principal)).rejects.toThrow(
      'Proposal branch has an unsafe worktree.',
    );
  });

  test('rejects forged state, unsafe worktrees, and symlinked runtime roots', async () => {
    const repoRoot = tempRepo();
    const git = new FakeGit();
    const paths = __proposalWorkspaceTestExports.buildRecordPaths(
      repoRoot,
      principal.id,
      'proposal-1',
    );
    mkdirSync(dirname(paths.statePath), { recursive: true });
    writeFileSync(
      paths.statePath,
      JSON.stringify({
        version: 1,
        proposalId: 'proposal-1',
        principalId: 'human:forged',
        branch: paths.branch,
        worktreePath: paths.worktreePath,
        createdAt: '2026-08-05T12:00:00.000Z',
        updatedAt: '2026-08-05T12:00:00.000Z',
      }),
    );
    await expect(service(repoRoot, git).createOrResume(principal)).rejects.toMatchObject({
      code: 'proposal-owner-mismatch',
    });

    const unsafeRoot = tempRepo();
    const unsafeGit = new FakeGit();
    const unsafePaths = __proposalWorkspaceTestExports.buildRecordPaths(
      unsafeRoot,
      principal.id,
      'proposal-1',
    );
    unsafeGit.worktrees.push({
      path: join(unsafeRoot, 'elsewhere'),
      branch: unsafePaths.branch,
      headSha: 'abc',
      locked: false,
      prunable: false,
    });
    await expect(service(unsafeRoot, unsafeGit).createOrResume(principal)).rejects.toMatchObject({
      code: 'invalid-state',
    });

    const symlinkRoot = tempRepo();
    symlinkSync(tempRepo(), join(symlinkRoot, '.ok'));
    await expect(
      service(symlinkRoot, new FakeGit()).createOrResume(principal),
    ).rejects.toMatchObject({ code: 'unsafe-runtime-path' });
  });

  test('rejects invalid state topology and non-regular state files', async () => {
    const repoRoot = tempRepo();
    const git = new FakeGit();
    const paths = __proposalWorkspaceTestExports.buildRecordPaths(
      repoRoot,
      principal.id,
      'proposal-1',
    );
    mkdirSync(dirname(paths.statePath), { recursive: true });
    writeFileSync(
      paths.statePath,
      JSON.stringify({
        version: 1,
        proposalId: 'proposal-1',
        principalId: principal.id,
        branch: 'wrong/branch',
        worktreePath: paths.worktreePath,
        createdAt: '2026-08-05T12:00:00.000Z',
        updatedAt: '2026-08-05T12:00:00.000Z',
      }),
    );
    expect(() => service(repoRoot, git).get(principal, 'proposal-1')).toThrow(
      'Proposal state topology is invalid.',
    );

    const secondRoot = tempRepo();
    const secondPaths = __proposalWorkspaceTestExports.buildRecordPaths(
      secondRoot,
      principal.id,
      'proposal-1',
    );
    mkdirSync(secondPaths.statePath, { recursive: true });
    expect(() => service(secondRoot, new FakeGit()).get(principal, 'proposal-1')).toThrow(
      'Proposal state is not a regular file.',
    );

    const malformedRoot = tempRepo();
    const malformedPaths = __proposalWorkspaceTestExports.buildRecordPaths(
      malformedRoot,
      principal.id,
      'proposal-1',
    );
    mkdirSync(dirname(malformedPaths.statePath), { recursive: true });
    writeFileSync(malformedPaths.statePath, '{not json');
    expect(() => service(malformedRoot, new FakeGit()).get(principal, 'proposal-1')).toThrow(
      'Proposal state is invalid.',
    );
  });

  test('rolls back a newly-created worktree when state persistence fails', async () => {
    const repoRoot = tempRepo();
    const git = new FakeGit();
    const paths = __proposalWorkspaceTestExports.buildRecordPaths(
      repoRoot,
      principal.id,
      'proposal-1',
    );
    mkdirSync(dirname(paths.stateDir), { recursive: true });
    writeFileSync(paths.stateDir, 'blocks directory creation');

    await expect(service(repoRoot, git).createOrResume(principal)).rejects.toMatchObject({
      code: 'unsafe-runtime-path',
    });
    expect(git.removeCalls).toEqual([paths.worktreePath]);
    expect(git.deleteCalls).toEqual([paths.branch]);
  });

  test('preserves the persistence error when rollback cleanup also fails', async () => {
    const repoRoot = tempRepo();
    const git = new FakeGit();
    git.removeFailure = new Error('remove failed');
    git.deleteFailure = new Error('delete failed');
    const paths = __proposalWorkspaceTestExports.buildRecordPaths(
      repoRoot,
      principal.id,
      'proposal-1',
    );
    mkdirSync(dirname(paths.stateDir), { recursive: true });
    writeFileSync(paths.stateDir, 'blocks directory creation');
    await expect(service(repoRoot, git).createOrResume(principal)).rejects.toMatchObject({
      code: 'unsafe-runtime-path',
    });
    expect(git.removeCalls).toHaveLength(1);
    expect(git.deleteCalls).toHaveLength(1);
  });

  test('does not delete pre-existing Git state when registry persistence fails', async () => {
    const existingRoot = tempRepo();
    const existingGit = new FakeGit();
    const existingPaths = __proposalWorkspaceTestExports.buildRecordPaths(
      existingRoot,
      principal.id,
      'proposal-1',
    );
    existingGit.branches.add(existingPaths.branch);
    existingGit.worktrees.push({
      path: existingPaths.worktreePath,
      branch: existingPaths.branch,
      headSha: 'abc',
      locked: false,
      prunable: false,
    });
    mkdirSync(dirname(existingPaths.stateDir), { recursive: true });
    writeFileSync(existingPaths.stateDir, 'blocks directory creation');
    await expect(
      service(existingRoot, existingGit).createOrResume(principal),
    ).rejects.toMatchObject({
      code: 'unsafe-runtime-path',
    });
    expect(existingGit.removeCalls).toHaveLength(0);
    expect(existingGit.deleteCalls).toHaveLength(0);

    const branchRoot = tempRepo();
    const branchGit = new FakeGit();
    const branchPaths = __proposalWorkspaceTestExports.buildRecordPaths(
      branchRoot,
      principal.id,
      'proposal-1',
    );
    branchGit.branches.add(branchPaths.branch);
    mkdirSync(dirname(branchPaths.stateDir), { recursive: true });
    writeFileSync(branchPaths.stateDir, 'blocks directory creation');
    await expect(service(branchRoot, branchGit).createOrResume(principal)).rejects.toMatchObject({
      code: 'unsafe-runtime-path',
    });
    expect(branchGit.removeCalls).toHaveLength(1);
    expect(branchGit.deleteCalls).toHaveLength(0);
  });

  test('abandon is idempotent, protects dirty work, and removes clean work', async () => {
    const repoRoot = tempRepo();
    const git = new FakeGit();
    const workspaceService = service(repoRoot, git);
    await workspaceService.abandon(principal, 'proposal-1');
    await workspaceService.createOrResume(principal);
    git.dirty = true;
    await expect(workspaceService.abandon(principal, 'proposal-1')).rejects.toMatchObject({
      code: 'workspace-dirty',
    });
    git.dirty = false;
    await workspaceService.abandon(principal, 'proposal-1');
    expect(git.removeCalls).toHaveLength(1);
    expect(git.deleteCalls).toHaveLength(1);
    expect(workspaceService.get(principal, 'proposal-1')).toBeNull();
  });

  test('abandon recovers missing worktrees and rejects unsafe worktree topology', async () => {
    const repoRoot = tempRepo();
    const git = new FakeGit();
    const workspaceService = service(repoRoot, git);
    const workspace = await workspaceService.createOrResume(principal);
    git.worktrees = [{ ...git.worktrees[0], path: join(repoRoot, 'unsafe') }];
    await expect(workspaceService.abandon(principal, 'proposal-1')).rejects.toThrow(
      'Proposal branch has an unsafe worktree.',
    );

    git.worktrees = [];
    await workspaceService.abandon(principal, 'proposal-1');
    expect(git.removeCalls).toHaveLength(0);
    expect(git.deleteCalls).toEqual([workspace.record.branch]);

    const missingBranchRoot = tempRepo();
    const missingBranchGit = new FakeGit();
    const missingBranchService = service(missingBranchRoot, missingBranchGit);
    await missingBranchService.createOrResume(principal);
    missingBranchGit.worktrees = [];
    missingBranchGit.branches.clear();
    await missingBranchService.abandon(principal, 'proposal-1');
    expect(missingBranchGit.deleteCalls).toHaveLength(0);
  });

  test('uses secure default ids and timestamps when seams are omitted', async () => {
    const git = new FakeGit();
    const created = await createProposalWorkspaceService({
      repoRoot: tempRepo(),
      git,
    }).createOrResume(principal);
    expect(created.record.proposalId).toMatch(/^[a-f0-9-]{36}$/);
    expect(Number.isNaN(Date.parse(created.record.createdAt))).toBe(false);
  });

  test('does not convert git creation failures', async () => {
    const git = new FakeGit();
    git.createFailure = new Error('git failed');
    await expect(service(tempRepo(), git).createOrResume(principal)).rejects.toThrow('git failed');
  });

  test('creates and cleans a real Git worktree', async () => {
    const repoRoot = tempRepo();
    execFileSync('git', ['init', '--initial-branch=main'], { cwd: repoRoot });
    execFileSync('git', ['config', 'user.email', 'test@example.com'], { cwd: repoRoot });
    execFileSync('git', ['config', 'user.name', 'Test'], { cwd: repoRoot });
    writeFileSync(join(repoRoot, 'README.md'), '# Test\n');
    execFileSync('git', ['add', 'README.md'], { cwd: repoRoot });
    execFileSync('git', ['commit', '-m', 'initial'], { cwd: repoRoot });

    const workspaceService = createProposalWorkspaceService({
      repoRoot,
      createId: () => 'proposal-1',
      now: () => new Date('2026-08-05T12:00:00.000Z'),
    });
    const workspace = await workspaceService.createOrResume(principal);
    expect(readFileSync(join(workspace.record.worktreePath, 'README.md'), 'utf8')).toBe('# Test\n');
    execFileSync('git', ['worktree', 'remove', workspace.record.worktreePath], { cwd: repoRoot });
    const resumed = await workspaceService.createOrResume(principal);
    expect(resumed.created).toBe(true);
    await workspaceService.abandon(principal, 'proposal-1');
    expect(workspaceService.get(principal, 'proposal-1')).toBeNull();
  });

  test('propagates unexpected system Git branch lookup failures', async () => {
    await expect(
      __proposalWorkspaceTestExports.createSystemProposalGit(tempRepo()).branchExists('main'),
    ).rejects.toBeDefined();
  });
});
