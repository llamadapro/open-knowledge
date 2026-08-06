import { execFile } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { promisify } from 'node:util';
import {
  type BridgeWorktreeEntry,
  isValidBranchName,
  type KnowledgeRuntimeScope,
  ProposalIdSchema,
  parseWorktreeListPorcelain,
  type SecurityPrincipal,
  SecurityPrincipalIdSchema,
  SecurityPrincipalSchema,
} from '@inkeep/open-knowledge-core';
import { z } from 'zod';
import { withHiddenWindowsConsole } from '../child-process-windows-hide.ts';
import { buildGitEnv, withParentLock } from '../git-handle.ts';

const execFileAsync = promisify(execFile);
const PROPOSAL_BRANCH_PREFIX = 'ok/proposals';
const PROPOSAL_STATE_VERSION = 1;

export const ProposalWorkspaceRecordSchema = z.object({
  version: z.literal(PROPOSAL_STATE_VERSION),
  proposalId: ProposalIdSchema,
  principalId: SecurityPrincipalIdSchema,
  branch: z.string().min(1).max(255),
  worktreePath: z.string().min(1).max(4096),
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
});

export type ProposalWorkspaceRecord = z.infer<typeof ProposalWorkspaceRecordSchema>;

export interface ProposalWorkspace {
  record: ProposalWorkspaceRecord;
  runtimeScope: Extract<KnowledgeRuntimeScope, { kind: 'proposal' }>;
  created: boolean;
}

export interface ProposalWorkspaceGit {
  listWorktrees(): Promise<readonly BridgeWorktreeEntry[]>;
  branchExists(branch: string): Promise<boolean>;
  createWorktree(input: {
    branch: string;
    worktreePath: string;
    publishedBranch: string;
    createBranch: boolean;
  }): Promise<void>;
  isDirty(worktreePath: string): Promise<boolean>;
  removeWorktree(worktreePath: string): Promise<void>;
  deleteBranch(branch: string): Promise<void>;
}

export interface ProposalWorkspaceServiceOptions {
  repoRoot: string;
  publishedBranch?: string;
  git?: ProposalWorkspaceGit;
  now?: () => Date;
  createId?: () => string;
}

export class ProposalWorkspaceError extends Error {
  constructor(
    readonly code:
      | 'invalid-configuration'
      | 'invalid-principal'
      | 'invalid-proposal-id'
      | 'proposal-owner-mismatch'
      | 'invalid-state'
      | 'unsafe-runtime-path'
      | 'workspace-dirty',
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = 'ProposalWorkspaceError';
  }
}

export interface ProposalWorkspaceService {
  createOrResume(
    principal: SecurityPrincipal,
    options?: { proposalId?: string },
  ): Promise<ProposalWorkspace>;
  get(principal: SecurityPrincipal, proposalId: string): ProposalWorkspace | null;
  abandon(principal: SecurityPrincipal, proposalId: string): Promise<void>;
}

function principalKey(principalId: string): string {
  return createHash('sha256').update(principalId, 'utf8').digest('hex').slice(0, 20);
}

function assertContained(root: string, candidate: string): void {
  const rel = relative(root, candidate);
  if (rel === '' || (!rel.startsWith(`..${sep}`) && rel !== '..' && !isAbsolute(rel))) return;
  throw new ProposalWorkspaceError(
    'unsafe-runtime-path',
    'Proposal runtime path escaped its repository boundary.',
  );
}

function ensureContainedDirectory(repoRoot: string, dir: string): void {
  assertContained(repoRoot, dir);
  const rel = relative(repoRoot, dir);
  let cursor = repoRoot;
  for (const segment of rel.split(sep).filter(Boolean)) {
    cursor = join(cursor, segment);
    if (existsSync(cursor)) {
      const stat = lstatSync(cursor);
      if (stat.isSymbolicLink() || !stat.isDirectory()) {
        throw new ProposalWorkspaceError(
          'unsafe-runtime-path',
          'Proposal runtime path contains an unsafe component.',
        );
      }
      continue;
    }
    mkdirSync(cursor, { mode: 0o700 });
  }
  const canonical = realpathSync(dir);
  assertContained(repoRoot, canonical);
}

function buildRecordPaths(repoRoot: string, principalId: string, proposalId: string) {
  const key = principalKey(principalId);
  const branch = `${PROPOSAL_BRANCH_PREFIX}/${key}/${proposalId}`;
  const worktreePath = resolve(repoRoot, '.ok', 'worktrees', 'proposals', key, proposalId);
  const stateDir = resolve(repoRoot, '.ok', 'local', 'proposals', key);
  const statePath = resolve(stateDir, `${proposalId}.json`);
  for (const candidate of [worktreePath, stateDir, statePath]) assertContained(repoRoot, candidate);
  return { branch, worktreePath, stateDir, statePath };
}

function readRecord(statePath: string): ProposalWorkspaceRecord | null {
  if (!existsSync(statePath)) return null;
  try {
    const stat = lstatSync(statePath);
    if (!stat.isFile()) {
      throw new ProposalWorkspaceError('invalid-state', 'Proposal state is not a regular file.');
    }
    return ProposalWorkspaceRecordSchema.parse(JSON.parse(readFileSync(statePath, 'utf8')));
  } catch (cause) {
    if (cause instanceof ProposalWorkspaceError) throw cause;
    throw new ProposalWorkspaceError('invalid-state', 'Proposal state is invalid.', { cause });
  }
}

function writeRecord(
  repoRoot: string,
  stateDir: string,
  statePath: string,
  record: ProposalWorkspaceRecord,
): void {
  ensureContainedDirectory(repoRoot, stateDir);
  const tmpPath = join(stateDir, `.${record.proposalId}.${randomUUID()}.tmp`);
  assertContained(repoRoot, tmpPath);
  try {
    writeFileSync(tmpPath, `${JSON.stringify(record, null, 2)}\n`, {
      encoding: 'utf8',
      mode: 0o600,
      flag: 'wx',
    });
    renameSync(tmpPath, statePath);
  } finally {
    rmSync(tmpPath, { force: true });
  }
}

function toWorkspace(record: ProposalWorkspaceRecord, created: boolean): ProposalWorkspace {
  return {
    record,
    runtimeScope: {
      kind: 'proposal',
      proposalId: record.proposalId,
      principalId: record.principalId,
      branch: record.branch,
    },
    created,
  };
}

function validateOwnerAndTopology(
  record: ProposalWorkspaceRecord,
  principal: SecurityPrincipal,
  expected: ReturnType<typeof buildRecordPaths>,
): void {
  if (record.principalId !== principal.id) {
    throw new ProposalWorkspaceError(
      'proposal-owner-mismatch',
      'Proposal belongs to another principal.',
    );
  }
  if (record.branch !== expected.branch || resolve(record.worktreePath) !== expected.worktreePath) {
    throw new ProposalWorkspaceError('invalid-state', 'Proposal state topology is invalid.');
  }
}

export function createProposalWorkspaceService(
  options: ProposalWorkspaceServiceOptions,
): ProposalWorkspaceService {
  if (!isAbsolute(options.repoRoot)) {
    throw new ProposalWorkspaceError(
      'invalid-configuration',
      'Proposal repository root must be absolute.',
    );
  }
  const repoRoot = realpathSync(options.repoRoot);
  const publishedBranch = options.publishedBranch?.trim() || 'main';
  if (!isValidBranchName(publishedBranch)) {
    throw new ProposalWorkspaceError('invalid-configuration', 'Published branch is invalid.');
  }
  const git = options.git ?? createSystemProposalGit(repoRoot);
  const now = options.now ?? (() => new Date());
  const createId = options.createId ?? randomUUID;

  function validateRequest(principal: SecurityPrincipal, proposalId: string): void {
    if (!SecurityPrincipalSchema.safeParse(principal).success) {
      throw new ProposalWorkspaceError('invalid-principal', 'Proposal principal is invalid.');
    }
    if (!ProposalIdSchema.safeParse(proposalId).success) {
      throw new ProposalWorkspaceError('invalid-proposal-id', 'Proposal id is invalid.');
    }
  }

  return {
    async createOrResume(principal, createOptions = {}) {
      const proposalId = createOptions.proposalId ?? createId();
      validateRequest(principal, proposalId);
      const paths = buildRecordPaths(repoRoot, principal.id, proposalId);

      return await withParentLock(async () => {
        const existing = readRecord(paths.statePath);
        if (existing) {
          validateOwnerAndTopology(existing, principal, paths);
          const worktrees = await git.listWorktrees();
          const existingWorktree = worktrees.find((entry) => entry.branch === paths.branch);
          if (existingWorktree && resolve(existingWorktree.path) !== paths.worktreePath) {
            throw new ProposalWorkspaceError(
              'invalid-state',
              'Proposal branch has an unsafe worktree.',
            );
          }
          if (existingWorktree) return toWorkspace(existing, false);
          if (!(await git.branchExists(paths.branch))) {
            throw new ProposalWorkspaceError(
              'invalid-state',
              'Proposal state references a missing Git branch.',
            );
          }
          ensureContainedDirectory(repoRoot, resolve(paths.worktreePath, '..'));
          await git.createWorktree({
            branch: paths.branch,
            worktreePath: paths.worktreePath,
            publishedBranch,
            createBranch: false,
          });
          const resumed = { ...existing, updatedAt: now().toISOString() };
          writeRecord(repoRoot, paths.stateDir, paths.statePath, resumed);
          return toWorkspace(resumed, true);
        }

        const worktrees = await git.listWorktrees();
        const existingWorktree = worktrees.find((entry) => entry.branch === paths.branch);
        if (existingWorktree && resolve(existingWorktree.path) !== paths.worktreePath) {
          throw new ProposalWorkspaceError(
            'invalid-state',
            'Proposal branch has an unsafe worktree.',
          );
        }

        const branchExists = await git.branchExists(paths.branch);
        let createdWorktree = false;
        if (!existingWorktree) {
          ensureContainedDirectory(repoRoot, resolve(paths.worktreePath, '..'));
          await git.createWorktree({
            branch: paths.branch,
            worktreePath: paths.worktreePath,
            publishedBranch,
            createBranch: !branchExists,
          });
          createdWorktree = true;
        }

        const timestamp = now().toISOString();
        const record = ProposalWorkspaceRecordSchema.parse({
          version: PROPOSAL_STATE_VERSION,
          proposalId,
          principalId: principal.id,
          branch: paths.branch,
          worktreePath: paths.worktreePath,
          createdAt: timestamp,
          updatedAt: timestamp,
        });
        try {
          writeRecord(repoRoot, paths.stateDir, paths.statePath, record);
        } catch (cause) {
          if (createdWorktree) {
            await git.removeWorktree(paths.worktreePath).catch(() => undefined);
            if (!branchExists) await git.deleteBranch(paths.branch).catch(() => undefined);
          }
          throw cause;
        }
        return toWorkspace(record, createdWorktree);
      });
    },

    get(principal, proposalId) {
      validateRequest(principal, proposalId);
      const paths = buildRecordPaths(repoRoot, principal.id, proposalId);
      const record = readRecord(paths.statePath);
      if (!record) return null;
      validateOwnerAndTopology(record, principal, paths);
      return toWorkspace(record, false);
    },

    async abandon(principal, proposalId) {
      validateRequest(principal, proposalId);
      const paths = buildRecordPaths(repoRoot, principal.id, proposalId);
      await withParentLock(async () => {
        const record = readRecord(paths.statePath);
        if (!record) return;
        validateOwnerAndTopology(record, principal, paths);
        const worktrees = await git.listWorktrees();
        const worktree = worktrees.find((entry) => entry.branch === paths.branch);
        if (worktree && resolve(worktree.path) !== paths.worktreePath) {
          throw new ProposalWorkspaceError(
            'invalid-state',
            'Proposal branch has an unsafe worktree.',
          );
        }
        if (worktree) {
          if (await git.isDirty(paths.worktreePath)) {
            throw new ProposalWorkspaceError(
              'workspace-dirty',
              'Proposal contains uncommitted changes and cannot be cleaned automatically.',
            );
          }
          await git.removeWorktree(paths.worktreePath);
        }
        if (await git.branchExists(paths.branch)) await git.deleteBranch(paths.branch);
        rmSync(paths.statePath, { force: true });
      });
    },
  };
}

function createSystemProposalGit(repoRoot: string): ProposalWorkspaceGit {
  async function run(args: string[], cwd = repoRoot): Promise<string> {
    const result = await execFileAsync(
      'git',
      ['-c', 'credential.interactive=false', ...args],
      withHiddenWindowsConsole({
        cwd,
        env: buildGitEnv(),
        maxBuffer: 4 * 1024 * 1024,
        timeout: 30_000,
      }),
    );
    return result.stdout;
  }

  return {
    async listWorktrees() {
      return parseWorktreeListPorcelain(await run(['worktree', 'list', '--porcelain']));
    },
    async branchExists(branch) {
      try {
        await run(['show-ref', '--verify', '--quiet', `refs/heads/${branch}`]);
        return true;
      } catch (error) {
        if ((error as NodeJS.ErrnoException & { code?: number }).code === 1) return false;
        throw error;
      }
    },
    async createWorktree(input) {
      const args = input.createBranch
        ? [
            'worktree',
            'add',
            '-b',
            input.branch,
            '--',
            input.worktreePath,
            `refs/heads/${input.publishedBranch}`,
          ]
        : ['worktree', 'add', '--', input.worktreePath, input.branch];
      await run(args);
    },
    async isDirty(worktreePath) {
      return (await run(['status', '--porcelain=v1'], worktreePath)).trim().length > 0;
    },
    async removeWorktree(worktreePath) {
      await run(['worktree', 'remove', worktreePath]);
    },
    async deleteBranch(branch) {
      await run(['branch', '-D', '--', branch]);
    },
  };
}

export const __proposalWorkspaceTestExports = {
  assertContained,
  buildRecordPaths,
  createSystemProposalGit,
  principalKey,
};
