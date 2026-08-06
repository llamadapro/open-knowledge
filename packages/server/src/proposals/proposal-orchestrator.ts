import { createHash } from 'node:crypto';
import {
  hasKnowledgeCapability,
  type KnowledgeRuntimeScope,
  type SecurityPrincipal,
  SecurityPrincipalSchema,
} from '@inkeep/open-knowledge-core';
import { z } from 'zod';
import type { ProposalWorkspace, ProposalWorkspaceService } from './proposal-workspace.ts';

const SAFE_RUNTIME_ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]*$/;

const ProposalRuntimeUrlSchema = z
  .url()
  .max(2048)
  .refine((value) => {
    const url = new URL(value);
    return (
      (url.protocol === 'https:' || url.protocol === 'http:') &&
      url.username === '' &&
      url.password === '' &&
      url.search === '' &&
      url.hash === ''
    );
  }, 'runtime URL must be a credential-free HTTP(S) origin or path');

export const ProposalRuntimeDescriptorSchema = z
  .object({
    runtimeId: z.string().min(1).max(512).regex(SAFE_RUNTIME_ID),
    state: z.enum(['starting', 'ready', 'failed', 'stopping']),
    updatedAt: z.iso.datetime(),
    browserUrl: ProposalRuntimeUrlSchema.optional(),
    mcpUrl: ProposalRuntimeUrlSchema.optional(),
    message: z.string().min(1).max(512).optional(),
  })
  .superRefine((descriptor, context) => {
    if (
      descriptor.state === 'ready' &&
      descriptor.browserUrl === undefined &&
      descriptor.mcpUrl === undefined
    ) {
      context.addIssue({
        code: 'custom',
        path: ['browserUrl'],
        message: 'ready proposal runtimes require a browser or MCP URL',
      });
    }
  });

export type ProposalRuntimeDescriptor = z.infer<typeof ProposalRuntimeDescriptorSchema>;

export interface ProposalRuntimeTarget {
  /** Stable, opaque infrastructure idempotency key. */
  runtimeKey: string;
  runtimeScope: Extract<KnowledgeRuntimeScope, { kind: 'proposal' }>;
}

export interface ProposalRuntimeLaunchInput extends ProposalRuntimeTarget {
  /** Trusted path produced by ProposalWorkspaceService, never caller input. */
  projectDir: string;
}

/**
 * Deployment adapter for a dedicated proposal runtime. Implementations may
 * use a local child process, container platform, or another isolated runtime,
 * but `ensureRunning` and `stop` must be idempotent for `runtimeKey`.
 */
export interface ProposalRuntimeProvisioner {
  ensureRunning(input: ProposalRuntimeLaunchInput): Promise<ProposalRuntimeDescriptor>;
  inspect(input: ProposalRuntimeTarget): Promise<ProposalRuntimeDescriptor | null>;
  stop(input: ProposalRuntimeTarget): Promise<void>;
}

export interface ProposalSession {
  proposalId: string;
  branch: string;
  createdAt: string;
  updatedAt: string;
  runtime: ProposalRuntimeDescriptor;
}

export interface ProposalOrchestrator {
  startOrResume(
    principal: SecurityPrincipal,
    options?: { proposalId?: string },
  ): Promise<ProposalSession>;
  get(principal: SecurityPrincipal, proposalId: string): Promise<ProposalSession | null>;
  abandon(principal: SecurityPrincipal, proposalId: string): Promise<void>;
}

export class ProposalOrchestratorError extends Error {
  constructor(
    readonly code:
      | 'invalid-principal'
      | 'proposal-capability-required'
      | 'invalid-runtime-descriptor'
      | 'runtime-provisioning-failed',
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = 'ProposalOrchestratorError';
  }
}

function requireProposalPrincipal(principal: SecurityPrincipal): void {
  if (!SecurityPrincipalSchema.safeParse(principal).success) {
    throw new ProposalOrchestratorError('invalid-principal', 'Proposal principal is invalid.');
  }
  if (!hasKnowledgeCapability(principal, 'knowledge.propose')) {
    throw new ProposalOrchestratorError(
      'proposal-capability-required',
      'The knowledge.propose capability is required.',
    );
  }
}

function runtimeKeyFor(scope: Extract<KnowledgeRuntimeScope, { kind: 'proposal' }>): string {
  return runtimeKeyForIdentity(scope.principalId, scope.proposalId);
}

function runtimeKeyForIdentity(principalId: string, proposalId: string): string {
  return createHash('sha256').update(`${principalId}\0${proposalId}`, 'utf8').digest('hex');
}

function runtimeTarget(workspace: ProposalWorkspace): ProposalRuntimeTarget {
  return {
    runtimeKey: runtimeKeyFor(workspace.runtimeScope),
    runtimeScope: workspace.runtimeScope,
  };
}

function parseRuntimeDescriptor(candidate: unknown): ProposalRuntimeDescriptor {
  const parsed = ProposalRuntimeDescriptorSchema.safeParse(candidate);
  if (!parsed.success) {
    throw new ProposalOrchestratorError(
      'invalid-runtime-descriptor',
      'Proposal runtime returned an invalid descriptor.',
      { cause: parsed.error },
    );
  }
  return parsed.data;
}

function toSession(
  workspace: ProposalWorkspace,
  runtime: ProposalRuntimeDescriptor,
): ProposalSession {
  return {
    proposalId: workspace.record.proposalId,
    branch: workspace.record.branch,
    createdAt: workspace.record.createdAt,
    updatedAt: workspace.record.updatedAt,
    runtime,
  };
}

export function createProposalOrchestrator(options: {
  workspaces: ProposalWorkspaceService;
  provisioner: ProposalRuntimeProvisioner;
}): ProposalOrchestrator {
  const lifecycleTails = new Map<string, Promise<void>>();
  const pendingStarts = new Map<string, Promise<ProposalSession>>();

  async function serializeLifecycle<Result>(
    runtimeKey: string,
    operation: () => Promise<Result>,
  ): Promise<Result> {
    const previous = lifecycleTails.get(runtimeKey) ?? Promise.resolve();
    const result = previous.then(operation);
    const tail = result.then(
      () => undefined,
      () => undefined,
    );
    lifecycleTails.set(runtimeKey, tail);
    try {
      return await result;
    } finally {
      if (lifecycleTails.get(runtimeKey) === tail) lifecycleTails.delete(runtimeKey);
    }
  }

  async function ensureRuntime(workspace: ProposalWorkspace): Promise<ProposalSession> {
    const target = runtimeTarget(workspace);
    try {
      const candidate = await options.provisioner.ensureRunning({
        ...target,
        projectDir: workspace.record.worktreePath,
      });
      return toSession(workspace, parseRuntimeDescriptor(candidate));
    } catch (cause) {
      if (cause instanceof ProposalOrchestratorError) throw cause;
      throw new ProposalOrchestratorError(
        'runtime-provisioning-failed',
        'Proposal runtime could not be started.',
        { cause },
      );
    }
  }

  async function startKnownProposal(
    principal: SecurityPrincipal,
    proposalId: string,
  ): Promise<ProposalSession> {
    const runtimeKey = runtimeKeyForIdentity(principal.id, proposalId);
    const existing = pendingStarts.get(runtimeKey);
    if (existing) return await existing;
    const operation = serializeLifecycle(runtimeKey, async () => {
      const workspace = await options.workspaces.createOrResume(principal, { proposalId });
      return await ensureRuntime(workspace);
    });
    pendingStarts.set(runtimeKey, operation);
    try {
      return await operation;
    } finally {
      pendingStarts.delete(runtimeKey);
    }
  }

  return {
    async startOrResume(principal, startOptions = {}) {
      requireProposalPrincipal(principal);
      if (startOptions.proposalId !== undefined) {
        return await startKnownProposal(principal, startOptions.proposalId);
      }
      const workspace = await options.workspaces.createOrResume(principal, startOptions);
      const target = runtimeTarget(workspace);
      return await serializeLifecycle(
        target.runtimeKey,
        async () => await ensureRuntime(workspace),
      );
    },

    async get(principal, proposalId) {
      requireProposalPrincipal(principal);
      const runtimeKey = runtimeKeyForIdentity(principal.id, proposalId);
      const pendingLifecycle = lifecycleTails.get(runtimeKey);
      if (pendingLifecycle) await pendingLifecycle;
      const workspace = options.workspaces.get(principal, proposalId);
      if (!workspace) return null;
      const runtime = await options.provisioner.inspect(runtimeTarget(workspace));
      return runtime ? toSession(workspace, parseRuntimeDescriptor(runtime)) : null;
    },

    async abandon(principal, proposalId) {
      requireProposalPrincipal(principal);
      const runtimeKey = runtimeKeyForIdentity(principal.id, proposalId);
      await serializeLifecycle(runtimeKey, async () => {
        const workspace = options.workspaces.get(principal, proposalId);
        if (!workspace) return;
        await options.provisioner.stop(runtimeTarget(workspace));
        await options.workspaces.abandon(principal, proposalId);
      });
    },
  };
}

export const __proposalOrchestratorTestExports = {
  runtimeKeyFor,
  runtimeKeyForIdentity,
};
