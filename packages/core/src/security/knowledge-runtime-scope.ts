import { z } from 'zod';
import { isValidBranchName } from '../schemas/api/share.ts';
import { type SecurityPrincipal, SecurityPrincipalIdSchema } from './authorization.ts';

const KnowledgeBranchSchema = z
  .string()
  .min(1)
  .max(255)
  .refine(isValidBranchName, 'invalid branch name');

export const ProposalIdSchema = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/);

export const KnowledgeRuntimeScopeSchema = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('published'),
    branch: KnowledgeBranchSchema,
  }),
  z.object({
    kind: z.literal('proposal'),
    proposalId: ProposalIdSchema,
    principalId: SecurityPrincipalIdSchema,
    branch: KnowledgeBranchSchema,
  }),
]);

export type KnowledgeRuntimeScope = z.infer<typeof KnowledgeRuntimeScopeSchema>;

export type KnowledgeMutationScopeDecision =
  | { allowed: true }
  | {
      allowed: false;
      reason: 'published-workspace-read-only';
      workspaceKind: 'published';
    }
  | {
      allowed: false;
      reason: 'proposal-principal-mismatch';
      workspaceKind: 'proposal';
      proposalId: string;
    };

/**
 * Decide whether an authenticated principal may mutate this runtime's files.
 * An omitted scope is the original local single-user mode. Shared deployments
 * always resolve an explicit published or proposal scope before serving.
 */
export function decideKnowledgeMutationScope(
  principal: SecurityPrincipal,
  scope: KnowledgeRuntimeScope | undefined,
): KnowledgeMutationScopeDecision {
  if (scope === undefined) return { allowed: true };
  if (scope.kind === 'published') {
    return {
      allowed: false,
      reason: 'published-workspace-read-only',
      workspaceKind: 'published',
    };
  }
  if (scope.principalId !== principal.id) {
    return {
      allowed: false,
      reason: 'proposal-principal-mismatch',
      workspaceKind: 'proposal',
      proposalId: scope.proposalId,
    };
  }
  return { allowed: true };
}
