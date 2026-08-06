import type { Extension } from '@hocuspocus/server';
import { hasKnowledgeCapability, type SecurityPrincipal } from '@inkeep/open-knowledge-core';
import { AuthenticationRequiredError, type AuthorizationService } from './authorization.ts';

export interface SecurityWebSocketContext {
  securityPrincipal?: SecurityPrincipal;
  principalId?: string;
  kind?: string;
  [key: string]: unknown;
}

export function createHocuspocusAuthorizationExtension(
  authorization: AuthorizationService,
): Extension<SecurityWebSocketContext> & { __kind: 'security-authorization' } {
  return {
    __kind: 'security-authorization',
    extensionName: 'security-authorization',

    async onAuthenticate({ token, context, documentName, connectionConfig }) {
      const authContext = {
        transport: 'websocket' as const,
        resource: `document:${documentName}`,
      };
      const principal = await authorization.authenticateToken(token, authContext);
      await authorization.requireCapability(principal, 'knowledge.read', authContext);
      context.securityPrincipal = principal;
      context.principalId = principal.id;
      context.kind = principal.kind;

      // Hocuspocus rejects client updates before they mutate the Y.Doc when a
      // connection is read-only. The onChange check below remains a second
      // boundary in case a framework upgrade regresses that enforcement.
      if (!hasKnowledgeCapability(principal, 'knowledge.propose')) {
        connectionConfig.readOnly = true;
      }
    },

    async onChange({ context, documentName, connection }) {
      // Server-originated reconciliation and file-watcher transactions do not
      // carry a connection and remain available to the trusted runtime.
      if (!connection) return;
      const principal = context.securityPrincipal;
      if (!principal) throw new AuthenticationRequiredError('invalid-principal');
      await authorization.requireCapability(principal, 'knowledge.propose', {
        transport: 'websocket',
        resource: `document:${documentName}:mutation`,
      });
    },
  };
}
