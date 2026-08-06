import {
  decideKnowledgeMutationScope,
  type KnowledgeRuntimeScope,
  type SecurityPrincipal,
} from '@inkeep/open-knowledge-core';
import {
  type AuthenticationContext,
  AuthorizationDeniedError,
  type SecurityAuditSink,
} from './authorization.ts';

export interface WorkspaceAuthorizationOptions {
  audit?: SecurityAuditSink;
  now?: () => Date;
}

/**
 * Enforce the filesystem workspace boundary after capability authorization.
 * Capability answers what an identity may do; scope answers where it may do
 * it. Keeping both checks separate makes a contributor on published `main`
 * read-only without weakening their ability to edit their proposal runtime.
 */
export async function requireKnowledgeMutationScope(
  principal: SecurityPrincipal,
  scope: KnowledgeRuntimeScope | undefined,
  context: AuthenticationContext,
  options: WorkspaceAuthorizationOptions = {},
): Promise<void> {
  const decision = decideKnowledgeMutationScope(principal, scope);
  if (decision.allowed) return;

  await options.audit?.({
    timestamp: (options.now ?? (() => new Date()))().toISOString(),
    event: 'security.workspace-authorization',
    outcome: 'denied',
    ...context,
    principalId: principal.id,
    capability: 'knowledge.propose',
    workspaceKind: decision.workspaceKind,
    ...(decision.workspaceKind === 'proposal' ? { proposalId: decision.proposalId } : {}),
    reason: decision.reason,
  });
  throw new AuthorizationDeniedError(principal.id, 'knowledge.propose', decision.reason);
}
