import { createHash } from 'node:crypto';
import {
  KNOWLEDGE_CAPABILITIES,
  type KnowledgeCapability,
  type SecurityPrincipal,
  SecurityPrincipalSchema,
} from '@inkeep/open-knowledge-core';
import { createRemoteJWKSet, errors, type JWTPayload, type JWTVerifyGetKey, jwtVerify } from 'jose';
import type { PrincipalAuthenticator } from './authorization.ts';

export interface Auth0MachinePrincipal {
  id: string;
  kind: 'agent' | 'service';
  displayName?: string;
}

export interface Auth0AuthenticatorOptions {
  /** Exact trusted Auth0 issuer. It is never derived from token claims. */
  issuer: string;
  /** API identifier configured as the Auth0 access-token audience. */
  audience: string;
  /** Explicit attribution for allowed client-credentials callers, keyed by Auth0 client id. */
  machinePrincipals?: Readonly<Record<string, Auth0MachinePrincipal>>;
  /** Injected only for deterministic tests or a trusted non-HTTP JWKS cache. */
  keySet?: JWTVerifyGetKey;
}

function normalizeTrustedIssuer(value: string): string {
  const issuer = new URL(value);
  if (
    issuer.protocol !== 'https:' ||
    issuer.username !== '' ||
    issuer.password !== '' ||
    issuer.search !== '' ||
    issuer.hash !== ''
  ) {
    throw new TypeError('Auth0 issuer must be a credential-free HTTPS URL.');
  }
  if (!issuer.pathname.endsWith('/')) issuer.pathname += '/';
  if (issuer.href.length > 2048) throw new TypeError('Auth0 issuer URL is too long.');
  return issuer.href;
}

function validateConfiguration(
  audience: string,
  machinePrincipals: Readonly<Record<string, Auth0MachinePrincipal>>,
): void {
  if (audience.trim().length === 0) throw new TypeError('Auth0 audience must not be empty.');
  for (const [clientId, machine] of Object.entries(machinePrincipals)) {
    if (clientId.trim().length === 0)
      throw new TypeError('Auth0 machine client id must not be empty.');
    const parsed = SecurityPrincipalSchema.safeParse({
      ...machine,
      issuer: 'https://configuration.invalid/',
      subject: clientId,
      capabilities: [],
    });
    if (!parsed.success || (machine.kind !== 'agent' && machine.kind !== 'service')) {
      throw new TypeError(`Invalid Auth0 machine principal configuration for client ${clientId}.`);
    }
  }
}

function capabilitiesFromPermissions(value: unknown): KnowledgeCapability[] {
  if (!Array.isArray(value)) return [];
  const permissions = new Set(
    value.filter((permission): permission is string => typeof permission === 'string'),
  );
  return KNOWLEDGE_CAPABILITIES.filter((capability) => permissions.has(capability));
}

function boundedDisplayName(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 && value.length <= 256 ? value : undefined;
}

function machineClientId(payload: JWTPayload): string | null | undefined {
  if (payload.gty !== 'client-credentials' && !payload.sub?.endsWith('@clients')) return undefined;
  if (typeof payload.client_id === 'string' && payload.client_id.length > 0)
    return payload.client_id;
  if (typeof payload.azp === 'string' && payload.azp.length > 0) return payload.azp;
  const suffix = '@clients';
  return payload.sub?.endsWith(suffix) ? payload.sub.slice(0, -suffix.length) || null : null;
}

function humanPrincipalId(subject: string): string {
  return `human:${createHash('sha256').update(subject).digest('base64url')}`;
}

function isRejectedCredential(error: unknown): boolean {
  return (
    error instanceof errors.JWTClaimValidationFailed ||
    error instanceof errors.JWTExpired ||
    error instanceof errors.JOSEAlgNotAllowed ||
    error instanceof errors.JWSInvalid ||
    error instanceof errors.JWTInvalid ||
    error instanceof errors.JWSSignatureVerificationFailed ||
    error instanceof errors.JWKSNoMatchingKey ||
    error instanceof errors.JOSENotSupported
  );
}

/**
 * Build an Auth0 adapter for the provider-neutral server authorization spine.
 *
 * Provider claims stop here: downstream HTTP, WebSocket, and MCP code receives
 * only a bounded `SecurityPrincipal`. Unknown permissions are ignored and
 * unregistered client-credentials callers fail closed.
 */
export function createAuth0PrincipalAuthenticator(
  options: Auth0AuthenticatorOptions,
): PrincipalAuthenticator {
  const issuer = normalizeTrustedIssuer(options.issuer);
  const machinePrincipals = options.machinePrincipals ?? {};
  validateConfiguration(options.audience, machinePrincipals);
  const keySet = options.keySet ?? createRemoteJWKSet(new URL('.well-known/jwks.json', issuer));

  return async ({ token }) => {
    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(token, keySet, {
        issuer,
        audience: options.audience,
        algorithms: ['RS256'],
        requiredClaims: ['exp', 'iat', 'sub'],
      }));
    } catch (error) {
      if (isRejectedCredential(error)) return null;
      throw error;
    }

    const subject = payload.sub;
    if (!subject || subject.length > 512) return null;
    const capabilities = capabilitiesFromPermissions(payload.permissions);
    const clientId = machineClientId(payload);
    if (clientId === null) return null;
    if (clientId !== undefined) {
      const configured = machinePrincipals[clientId];
      if (!configured) return null;
      return {
        ...configured,
        issuer,
        subject,
        capabilities,
      } satisfies SecurityPrincipal;
    }

    const displayName = boundedDisplayName(payload.name);
    return {
      id: humanPrincipalId(subject),
      kind: 'human',
      issuer,
      subject,
      ...(displayName ? { displayName } : {}),
      capabilities,
    } satisfies SecurityPrincipal;
  };
}
