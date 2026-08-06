import type { SecurityPrincipal } from '@inkeep/open-knowledge-core';
import { describe, expect, test, vi } from 'vitest';
import {
  AuthenticationRequiredError,
  AuthenticationUnavailableError,
  AuthorizationDeniedError,
  createAuthorizationService,
  parseBearerAuthorizationHeader,
  type SecurityAuditEvent,
} from './authorization.ts';

const reader: SecurityPrincipal = {
  id: 'agent:comito:prod',
  kind: 'agent',
  issuer: 'https://identity.example/',
  subject: 'client-id',
  capabilities: ['knowledge.read'],
};

const context = { transport: 'mcp' as const, resource: 'tool:search', requestId: 'req-1' };

describe('parseBearerAuthorizationHeader', () => {
  test('accepts an RFC 6750 bearer token', () => {
    expect(parseBearerAuthorizationHeader('Bearer abc.def-123_~+/==')).toEqual({
      ok: true,
      token: 'abc.def-123_~+/==',
    });
    expect(parseBearerAuthorizationHeader('bearer lowercase-scheme')).toEqual({
      ok: true,
      token: 'lowercase-scheme',
    });
  });

  test('classifies missing, repeated, oversized, and malformed headers', () => {
    expect(parseBearerAuthorizationHeader(undefined)).toEqual({ ok: false, reason: 'missing' });
    expect(parseBearerAuthorizationHeader(['Bearer one', 'Bearer two'])).toEqual({
      ok: false,
      reason: 'multiple',
    });
    expect(parseBearerAuthorizationHeader(`Bearer ${'a'.repeat(8193)}`)).toEqual({
      ok: false,
      reason: 'too-large',
    });
    expect(parseBearerAuthorizationHeader('Basic abc')).toEqual({
      ok: false,
      reason: 'malformed',
    });
    expect(parseBearerAuthorizationHeader('Bearer one,two')).toEqual({
      ok: false,
      reason: 'malformed',
    });
  });
});

describe('createAuthorizationService', () => {
  test('authenticates, authorizes, and emits bounded events without token bytes', async () => {
    const events: SecurityAuditEvent[] = [];
    const service = createAuthorizationService({
      authenticate: async () => reader,
      audit: (event) => events.push(event),
      now: () => new Date('2026-08-06T00:00:00.000Z'),
    });

    const principal = await service.authenticateBearer('Bearer secret-token', context);
    await service.requireCapability(principal, 'knowledge.read', context);

    expect(principal).toEqual(reader);
    expect(events).toEqual([
      {
        timestamp: '2026-08-06T00:00:00.000Z',
        event: 'security.authentication',
        outcome: 'allowed',
        ...context,
        principalId: reader.id,
      },
      {
        timestamp: '2026-08-06T00:00:00.000Z',
        event: 'security.authorization',
        outcome: 'allowed',
        ...context,
        principalId: reader.id,
        capability: 'knowledge.read',
      },
    ]);
    expect(JSON.stringify(events)).not.toContain('secret-token');
  });

  test('fails closed for missing, invalid, and malformed principals', async () => {
    const missing = createAuthorizationService({ authenticate: async () => reader });
    await expect(missing.authenticateBearer(undefined, context)).rejects.toBeInstanceOf(
      AuthenticationRequiredError,
    );

    const invalidToken = createAuthorizationService({ authenticate: async () => null });
    await expect(invalidToken.authenticateBearer('Bearer invalid', context)).rejects.toMatchObject({
      reason: 'invalid-token',
    });

    const invalidPrincipal = createAuthorizationService({
      authenticate: async () => ({ ...reader, id: 'human:wrong-kind' }),
    });
    await expect(
      invalidPrincipal.authenticateBearer('Bearer invalid-principal', context),
    ).rejects.toMatchObject({ reason: 'invalid-principal' });

    const authenticate = vi.fn(async () => reader);
    const invalidWebSocketToken = createAuthorizationService({ authenticate });
    await expect(invalidWebSocketToken.authenticateToken('', context)).rejects.toMatchObject({
      reason: 'malformed',
    });
    await expect(
      invalidWebSocketToken.authenticateToken('a'.repeat(8193), context),
    ).rejects.toMatchObject({ reason: 'too-large' });
    expect(authenticate).not.toHaveBeenCalled();
  });

  test('distinguishes identity-provider failure from bad credentials', async () => {
    const service = createAuthorizationService({
      authenticate: async () => {
        throw new Error('issuer unavailable');
      },
    });
    await expect(service.authenticateBearer('Bearer token', context)).rejects.toBeInstanceOf(
      AuthenticationUnavailableError,
    );
  });

  test('denies a missing capability and records the stable principal id only', async () => {
    const audit = vi.fn();
    const service = createAuthorizationService({ authenticate: async () => reader, audit });

    await expect(
      service.requireCapability(reader, 'knowledge.propose', context),
    ).rejects.toBeInstanceOf(AuthorizationDeniedError);
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'security.authorization',
        outcome: 'denied',
        principalId: reader.id,
        capability: 'knowledge.propose',
        reason: 'missing-capability',
      }),
    );
  });
});
