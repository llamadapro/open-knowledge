import type { KnowledgeRuntimeScope, SecurityPrincipal } from '@inkeep/open-knowledge-core';
import { describe, expect, test, vi } from 'vitest';
import { requireKnowledgeMutationScope } from './workspace-authorization.ts';

const principal: SecurityPrincipal = {
  id: 'agent:comito:prod',
  kind: 'agent',
  issuer: 'https://issuer.example/',
  subject: 'client-id',
  capabilities: ['knowledge.read', 'knowledge.propose'],
};
const context = { transport: 'mcp' as const, resource: 'tool:write', requestId: 'request-1' };

describe('requireKnowledgeMutationScope', () => {
  test('preserves local mode and permits the proposal owner', async () => {
    await expect(
      requireKnowledgeMutationScope(principal, undefined, context),
    ).resolves.toBeUndefined();
    await expect(
      requireKnowledgeMutationScope(
        principal,
        {
          kind: 'proposal',
          proposalId: 'proposal-1',
          principalId: principal.id,
          branch: 'ok/proposals/a/proposal-1',
        },
        context,
      ),
    ).resolves.toBeUndefined();
  });

  test.each([
    [
      { kind: 'published', branch: 'main' },
      'published-workspace-read-only',
      'Published knowledge is read-only. Start or resume a proposal before editing.',
    ],
    [
      {
        kind: 'proposal',
        proposalId: 'proposal-1',
        principalId: 'agent:someone-else:prod',
        branch: 'ok/proposals/other/proposal-1',
      },
      'proposal-principal-mismatch',
      'This proposal belongs to another principal.',
    ],
  ])('denies an invalid workspace scope %# and audits it', async (scope, reason, message) => {
    const audit = vi.fn();
    const operation = requireKnowledgeMutationScope(
      principal,
      scope as KnowledgeRuntimeScope,
      context,
      { audit, now: () => new Date('2026-08-05T12:00:00.000Z') },
    );

    await expect(operation).rejects.toMatchObject({
      name: 'AuthorizationDeniedError',
      reason,
      message,
    });
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({
        timestamp: '2026-08-05T12:00:00.000Z',
        event: 'security.workspace-authorization',
        outcome: 'denied',
        principalId: principal.id,
        reason,
      }),
    );
  });

  test('propagates audit failures without converting their error', async () => {
    const auditError = new Error('audit unavailable');
    await expect(
      requireKnowledgeMutationScope(principal, { kind: 'published', branch: 'main' }, context, {
        audit: () => {
          throw auditError;
        },
      }),
    ).rejects.toBe(auditError);
  });
});
