import { describe, expect, test } from 'vitest';
import {
  createCollaborationCredential,
  parseCollaborationCredential,
} from './collaboration-credential.ts';

describe('collaboration credential envelope', () => {
  test('preserves raw OAuth and legacy synchronization tokens', () => {
    expect(parseCollaborationCredential('jwt.token.signature')).toEqual({
      kind: 'raw',
      token: 'jwt.token.signature',
    });
    expect(parseCollaborationCredential('{"expectedBranch":"main"}')).toEqual({
      kind: 'raw',
      token: '{"expectedBranch":"main"}',
    });
  });

  test('round-trips a bearer token with and without a synchronization claim', () => {
    const withSync = createCollaborationCredential({
      bearerToken: 'jwt.token.signature',
      syncToken: '{"expectedBranch":"main"}',
    });
    expect(parseCollaborationCredential(withSync)).toEqual({
      kind: 'envelope',
      bearerToken: 'jwt.token.signature',
      syncToken: '{"expectedBranch":"main"}',
    });

    const bearerOnly = createCollaborationCredential({ bearerToken: 'jwt.token.signature' });
    expect(parseCollaborationCredential(bearerOnly)).toEqual({
      kind: 'envelope',
      bearerToken: 'jwt.token.signature',
    });
  });

  test('classifies missing and malformed values without throwing', () => {
    expect(parseCollaborationCredential(undefined)).toEqual({ kind: 'invalid', reason: 'missing' });
    expect(parseCollaborationCredential(null)).toEqual({ kind: 'invalid', reason: 'missing' });
    expect(parseCollaborationCredential('')).toEqual({ kind: 'invalid', reason: 'missing' });
    expect(parseCollaborationCredential('ok-auth-v1:not-json')).toEqual({
      kind: 'invalid',
      reason: 'malformed',
    });
    expect(parseCollaborationCredential('ok-auth-v1:{"bearerToken":"","extra":true}')).toEqual({
      kind: 'invalid',
      reason: 'malformed',
    });
  });

  test('rejects oversized bearer, sync, and combined envelopes', () => {
    const prefixed = (value: object) => `ok-auth-v1:${JSON.stringify(value)}`;
    expect(
      parseCollaborationCredential(prefixed({ bearerToken: 'x'.repeat(8 * 1024 + 1) })),
    ).toEqual({
      kind: 'invalid',
      reason: 'too-large',
    });
    expect(
      parseCollaborationCredential(
        prefixed({ bearerToken: 'jwt', syncToken: 'x'.repeat(16 * 1024 + 1) }),
      ),
    ).toEqual({ kind: 'invalid', reason: 'too-large' });
    expect(
      parseCollaborationCredential(
        prefixed({ bearerToken: 'b'.repeat(8 * 1024), syncToken: 's'.repeat(16 * 1024) }),
      ),
    ).toEqual({ kind: 'invalid', reason: 'too-large' });
  });

  test('refuses to serialize invalid envelopes', () => {
    expect(() => createCollaborationCredential({ bearerToken: '' })).toThrow(
      'Invalid collaboration credential: malformed.',
    );
    expect(() => createCollaborationCredential({ bearerToken: 'b'.repeat(8 * 1024 + 1) })).toThrow(
      'Invalid collaboration credential: too-large.',
    );
  });
});
