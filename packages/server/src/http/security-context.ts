import type { IncomingMessage } from 'node:http';
import type { SecurityPrincipal } from '@inkeep/open-knowledge-core';

const principals = new WeakMap<IncomingMessage, SecurityPrincipal>();

export function rememberSecurityPrincipal(
  request: IncomingMessage,
  principal: SecurityPrincipal,
): void {
  principals.set(request, principal);
}

export function getSecurityPrincipal(request: IncomingMessage): SecurityPrincipal | undefined {
  return principals.get(request);
}
