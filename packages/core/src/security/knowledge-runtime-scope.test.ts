import { describe, expect, test } from 'vitest';
import type { SecurityPrincipal } from './authorization.ts';
import {
  decideKnowledgeMutationScope,
  KnowledgeRuntimeScopeSchema,
  ProposalIdSchema,
} from './knowledge-runtime-scope.ts';

const principal: SecurityPrincipal = {
  id: 'human:auth0-abc',
  kind: 'human',
  issuer: 'https://issuer.example/',
  subject: 'auth0|abc',
  capabilities: ['knowledge.read', 'knowledge.propose'],
};

describe('KnowledgeRuntimeScopeSchema', () => {
  test('accepts bounded published and proposal scopes', () => {
    expect(KnowledgeRuntimeScopeSchema.parse({ kind: 'published', branch: 'main' })).toEqual({
      kind: 'published',
      branch: 'main',
    });
    expect(
      KnowledgeRuntimeScopeSchema.parse({
        kind: 'proposal',
        proposalId: 'proposal-123',
        principalId: principal.id,
        branch: 'ok/proposals/abc/proposal-123',
      }),
    ).toMatchObject({ kind: 'proposal', proposalId: 'proposal-123' });
  });

  test.each([
    { kind: 'published', branch: '../main' },
    { kind: 'proposal', proposalId: '../escape', principalId: principal.id, branch: 'main' },
    { kind: 'proposal', proposalId: 'valid', principalId: 'anonymous', branch: 'main' },
    {
      kind: 'proposal',
      proposalId: 'valid',
      principalId: principal.id,
      branch: '-main',
    },
  ])('rejects malformed scope %#', (scope) => {
    expect(KnowledgeRuntimeScopeSchema.safeParse(scope).success).toBe(false);
  });
});

describe('ProposalIdSchema', () => {
  test.each(['a', 'proposal-123', '018f7d74-19c3-7a4e-a914-818829b2d5ee'])('accepts %s', (value) =>
    expect(ProposalIdSchema.parse(value)).toBe(value));
  test.each([
    '',
    '-leading',
    'trailing-',
    'Uppercase',
    'with/slash',
    'x'.repeat(65),
  ])('rejects %s', (value) => expect(ProposalIdSchema.safeParse(value).success).toBe(false));
});

describe('decideKnowledgeMutationScope', () => {
  test('preserves the local single-user mutation posture', () => {
    expect(decideKnowledgeMutationScope(principal, undefined)).toEqual({ allowed: true });
  });

  test('makes the published runtime read-only', () => {
    expect(decideKnowledgeMutationScope(principal, { kind: 'published', branch: 'main' })).toEqual({
      allowed: false,
      reason: 'published-workspace-read-only',
      workspaceKind: 'published',
    });
  });

  test('permits only the proposal owner in a proposal runtime', () => {
    const scope = {
      kind: 'proposal' as const,
      proposalId: 'proposal-123',
      principalId: principal.id,
      branch: 'ok/proposals/owner/proposal-123',
    };
    expect(decideKnowledgeMutationScope(principal, scope)).toEqual({ allowed: true });
    expect(decideKnowledgeMutationScope({ ...principal, id: 'human:someone-else' }, scope)).toEqual(
      {
        allowed: false,
        reason: 'proposal-principal-mismatch',
        workspaceKind: 'proposal',
        proposalId: 'proposal-123',
      },
    );
  });
});
