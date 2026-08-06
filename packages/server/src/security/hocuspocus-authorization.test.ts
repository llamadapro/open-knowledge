import type { KnowledgeRuntimeScope } from '@inkeep/open-knowledge-core';
import { createCollaborationCredential, type SecurityPrincipal } from '@inkeep/open-knowledge-core';
import { describe, expect, test, vi } from 'vitest';
import { AuthenticationRequiredError, createAuthorizationService } from './authorization.ts';
import {
  createHocuspocusAuthorizationExtension,
  type SecurityWebSocketContext,
} from './hocuspocus-authorization.ts';

const reader: SecurityPrincipal = {
  id: 'human:reader',
  kind: 'human',
  issuer: 'test',
  subject: 'reader',
  capabilities: ['knowledge.read'],
};
const contributor: SecurityPrincipal = {
  ...reader,
  id: 'human:contributor',
  subject: 'contributor',
  capabilities: ['knowledge.read', 'knowledge.propose'],
};

function extension(runtimeScope?: KnowledgeRuntimeScope, workspaceAudit = vi.fn()) {
  return createHocuspocusAuthorizationExtension(
    createAuthorizationService({
      authenticate: async ({ token }) => {
        if (token === 'reader') return reader;
        if (token === 'contributor') return contributor;
        return null;
      },
    }),
    { runtimeScope, workspaceAudit },
  );
}

function authPayload(token: string, context: SecurityWebSocketContext, readOnly = false) {
  return {
    token,
    context,
    documentName: 'company/index',
    connectionConfig: { readOnly, isAuthenticated: false },
  } as never;
}

describe('Hocuspocus authorization extension', () => {
  test('authenticates a reader, propagates identity, and makes the connection read-only', async () => {
    const ext = extension();
    const context: SecurityWebSocketContext = {};
    const payload = authPayload('reader', context);
    await ext.onAuthenticate?.(payload);

    expect(context.securityPrincipal).toEqual(reader);
    expect(context.principalId).toBe(reader.id);
    expect(context.kind).toBe('human');
    expect((payload as { connectionConfig: { readOnly: boolean } }).connectionConfig.readOnly).toBe(
      true,
    );
  });

  test('preserves an existing read-only decision for a contributor', async () => {
    const ext = extension();
    const context: SecurityWebSocketContext = {};
    const payload = authPayload('contributor', context, true);
    await ext.onAuthenticate?.(payload);
    expect(context.securityPrincipal).toEqual(contributor);
    expect((payload as { connectionConfig: { readOnly: boolean } }).connectionConfig.readOnly).toBe(
      true,
    );
  });

  test('makes contributors read-only on published and foreign proposal runtimes', async () => {
    for (const runtimeScope of [
      { kind: 'published' as const, branch: 'main' },
      {
        kind: 'proposal' as const,
        proposalId: 'proposal-1',
        principalId: 'human:someone-else',
        branch: 'ok/proposals/other/proposal-1',
      },
    ]) {
      const ext = extension(runtimeScope);
      const payload = authPayload('contributor', {});
      await ext.onAuthenticate?.(payload);
      expect(
        (payload as { connectionConfig: { readOnly: boolean } }).connectionConfig.readOnly,
      ).toBe(true);
    }
  });

  test('keeps the proposal owner writable', async () => {
    const ext = extension({
      kind: 'proposal',
      proposalId: 'proposal-1',
      principalId: contributor.id,
      branch: 'ok/proposals/owner/proposal-1',
    });
    const payload = authPayload('contributor', {});
    await ext.onAuthenticate?.(payload);
    expect((payload as { connectionConfig: { readOnly: boolean } }).connectionConfig.readOnly).toBe(
      false,
    );
  });

  test('rejects an invalid token before placing identity in context', async () => {
    const ext = extension();
    const context: SecurityWebSocketContext = {};
    await expect(ext.onAuthenticate?.(authPayload('invalid', context))).rejects.toBeInstanceOf(
      AuthenticationRequiredError,
    );
    expect(context.securityPrincipal).toBeUndefined();
  });

  test('authenticates the bearer portion of a collaboration credential envelope', async () => {
    const ext = extension();
    const context: SecurityWebSocketContext = {};
    const token = createCollaborationCredential({
      bearerToken: 'contributor',
      syncToken: '{"expectedBranch":"main"}',
    });
    await ext.onAuthenticate?.(authPayload(token, context));
    expect(context.securityPrincipal).toEqual(contributor);
  });

  test('rejects malformed and oversized credential envelopes', async () => {
    const ext = extension();
    await expect(
      ext.onAuthenticate?.(authPayload('ok-auth-v1:not-json', {})),
    ).rejects.toMatchObject({ reason: 'malformed' });
    await expect(
      ext.onAuthenticate?.(
        authPayload(
          `ok-auth-v1:${JSON.stringify({ bearerToken: 'b'.repeat(8 * 1024), syncToken: 's'.repeat(16 * 1024) })}`,
          {},
        ),
      ),
    ).rejects.toMatchObject({ reason: 'too-large' });
  });

  test('requires proposal capability for client-originated mutations', async () => {
    const ext = extension({
      kind: 'proposal',
      proposalId: 'proposal-1',
      principalId: contributor.id,
      branch: 'ok/proposals/owner/proposal-1',
    });
    await expect(
      ext.onChange?.({
        context: { securityPrincipal: reader },
        documentName: 'company/index',
        connection: {},
      } as never),
    ).rejects.toMatchObject({ capability: 'knowledge.propose' });

    await expect(
      ext.onChange?.({
        context: { securityPrincipal: contributor },
        documentName: 'company/index',
        connection: {},
      } as never),
    ).resolves.toBeUndefined();
  });

  test('rejects published client mutations at the workspace boundary', async () => {
    const workspaceAudit = vi.fn();
    const ext = extension(undefined, workspaceAudit);
    await expect(
      ext.onChange?.({
        context: { securityPrincipal: contributor },
        documentName: 'company/index',
        connection: {},
      } as never),
    ).rejects.toMatchObject({ reason: 'published-workspace-read-only' });
    expect(workspaceAudit).toHaveBeenCalledWith(
      expect.objectContaining({ transport: 'websocket', workspaceKind: 'published' }),
    );
  });

  test('rejects a connected mutation when authentication context is missing', async () => {
    const ext = extension();
    await expect(
      ext.onChange?.({
        context: {},
        documentName: 'company/index',
        connection: {},
      } as never),
    ).rejects.toMatchObject({ reason: 'invalid-principal' });
  });

  test('allows trusted server-originated mutations without a connection principal', async () => {
    const ext = extension();
    await expect(
      ext.onChange?.({ context: {}, documentName: 'company/index' } as never),
    ).resolves.toBeUndefined();
  });
});
