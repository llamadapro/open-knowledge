import { describe, expect, test } from 'vitest';
import {
  defaultSharedKnowledgeRuntimeScope,
  KnowledgeRuntimeScopeConfigurationError,
  resolveKnowledgeRuntimeScope,
} from './runtime-scope.ts';

describe('defaultSharedKnowledgeRuntimeScope', () => {
  test('fails closed to published main and preserves an explicit scope', () => {
    expect(defaultSharedKnowledgeRuntimeScope(undefined)).toEqual({
      kind: 'published',
      branch: 'main',
    });
    const proposal = {
      kind: 'proposal' as const,
      proposalId: 'proposal-1',
      principalId: 'human:owner',
      branch: 'ok/proposals/owner/proposal-1',
    };
    expect(defaultSharedKnowledgeRuntimeScope(proposal)).toBe(proposal);
  });
});

describe('resolveKnowledgeRuntimeScope', () => {
  test('preserves unscoped local mode', () => {
    expect(resolveKnowledgeRuntimeScope({ authorizationConfigured: false })).toBeUndefined();
  });

  test('defaults an authenticated server to published main', () => {
    expect(resolveKnowledgeRuntimeScope({ authorizationConfigured: true })).toEqual({
      kind: 'published',
      branch: 'main',
    });
  });

  test('accepts an explicit published branch and proposal scope', () => {
    expect(
      resolveKnowledgeRuntimeScope({
        authorizationConfigured: true,
        publishedBranch: 'stable',
      }),
    ).toEqual({ kind: 'published', branch: 'stable' });
    expect(
      resolveKnowledgeRuntimeScope({
        authorizationConfigured: true,
        publishedBranch: '   ',
      }),
    ).toEqual({ kind: 'published', branch: 'main' });
    expect(
      resolveKnowledgeRuntimeScope({
        authorizationConfigured: true,
        explicitScope: {
          kind: 'proposal',
          proposalId: 'proposal-1',
          principalId: 'human:owner',
          branch: 'ok/proposals/owner/proposal-1',
        },
      }),
    ).toMatchObject({ kind: 'proposal', proposalId: 'proposal-1' });
  });

  test('rejects scope configuration without authentication', () => {
    expect(() =>
      resolveKnowledgeRuntimeScope({
        authorizationConfigured: false,
        publishedBranch: 'main',
      }),
    ).toThrow(KnowledgeRuntimeScopeConfigurationError);
    expect(() =>
      resolveKnowledgeRuntimeScope({
        authorizationConfigured: false,
        explicitScope: { kind: 'published', branch: 'main' },
      }),
    ).toThrow('Knowledge runtime scope requires shared-server authentication.');
  });

  test('rejects malformed hosted branches', () => {
    expect(() =>
      resolveKnowledgeRuntimeScope({
        authorizationConfigured: true,
        publishedBranch: '../main',
      }),
    ).toThrow('Knowledge runtime scope is invalid.');
  });
});
