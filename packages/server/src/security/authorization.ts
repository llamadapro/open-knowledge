import {
  hasKnowledgeCapability,
  type KnowledgeCapability,
  type SecurityPrincipal,
  SecurityPrincipalSchema,
} from '@inkeep/open-knowledge-core';

export type SecurityTransport = 'http' | 'websocket' | 'mcp';

export interface AuthenticationContext {
  transport: SecurityTransport;
  resource: string;
  requestId?: string;
}

export interface PrincipalAuthenticationInput extends AuthenticationContext {
  token: string;
}

export type PrincipalAuthenticator = (
  input: PrincipalAuthenticationInput,
) => Promise<SecurityPrincipal | null>;

export type SecurityAuditEvent =
  | {
      timestamp: string;
      event: 'security.authentication';
      outcome: 'allowed' | 'denied' | 'error';
      transport: SecurityTransport;
      resource: string;
      requestId?: string;
      principalId?: string;
      reason?: BearerFailureReason | 'invalid-token' | 'invalid-principal' | 'provider-error';
    }
  | {
      timestamp: string;
      event: 'security.authorization';
      outcome: 'allowed' | 'denied';
      transport: SecurityTransport;
      resource: string;
      requestId?: string;
      principalId: string;
      capability: KnowledgeCapability;
      reason?: 'missing-capability';
    };

export type SecurityAuditSink = (event: SecurityAuditEvent) => void | Promise<void>;

export type BearerFailureReason = 'missing' | 'multiple' | 'malformed' | 'too-large';

export type BearerParseResult =
  | { ok: true; token: string }
  | { ok: false; reason: BearerFailureReason };

const MAX_AUTHORIZATION_HEADER_BYTES = 8 * 1024;
const OAUTH_BEARER_TOKEN = /^[A-Za-z0-9\-._~+/]+=*$/;

function validateTokenShape(token: string): BearerFailureReason | undefined {
  if (Buffer.byteLength(token, 'utf8') > MAX_AUTHORIZATION_HEADER_BYTES) return 'too-large';
  if (!OAUTH_BEARER_TOKEN.test(token)) return 'malformed';
  return undefined;
}

export function parseBearerAuthorizationHeader(
  header: string | string[] | undefined,
): BearerParseResult {
  if (header === undefined) return { ok: false, reason: 'missing' };
  if (Array.isArray(header)) return { ok: false, reason: 'multiple' };
  if (Buffer.byteLength(header, 'utf8') > MAX_AUTHORIZATION_HEADER_BYTES) {
    return { ok: false, reason: 'too-large' };
  }

  const match = /^Bearer ([^\s]+)$/i.exec(header);
  if (!match?.[1] || validateTokenShape(match[1])) {
    return { ok: false, reason: 'malformed' };
  }
  return { ok: true, token: match[1] };
}

export class AuthenticationRequiredError extends Error {
  readonly statusCode = 401;
  readonly code = 'authentication-required';

  constructor(readonly reason: BearerFailureReason | 'invalid-token' | 'invalid-principal') {
    super('Authentication required.');
    this.name = 'AuthenticationRequiredError';
  }
}

export class AuthenticationUnavailableError extends Error {
  readonly statusCode = 503;
  readonly code = 'authentication-unavailable';

  constructor(options?: ErrorOptions) {
    super('Authentication service unavailable.', options);
    this.name = 'AuthenticationUnavailableError';
  }
}

export class AuthorizationDeniedError extends Error {
  readonly statusCode = 403;
  readonly code = 'authorization-denied';

  constructor(
    readonly principalId: string,
    readonly capability: KnowledgeCapability,
  ) {
    super('Insufficient capability.');
    this.name = 'AuthorizationDeniedError';
  }
}

export interface AuthorizationService {
  authenticateToken: (token: string, context: AuthenticationContext) => Promise<SecurityPrincipal>;
  authenticateBearer: (
    header: string | string[] | undefined,
    context: AuthenticationContext,
  ) => Promise<SecurityPrincipal>;
  requireCapability: (
    principal: SecurityPrincipal,
    capability: KnowledgeCapability,
    context: AuthenticationContext,
  ) => Promise<void>;
}

export function createAuthorizationService(options: {
  authenticate: PrincipalAuthenticator;
  audit?: SecurityAuditSink;
  now?: () => Date;
}): AuthorizationService {
  const now = options.now ?? (() => new Date());
  type AuditInput<Event> = Event extends SecurityAuditEvent ? Omit<Event, 'timestamp'> : never;
  const emit = async (event: AuditInput<SecurityAuditEvent>): Promise<void> => {
    await options.audit?.({ ...event, timestamp: now().toISOString() } as SecurityAuditEvent);
  };

  const authenticateToken = async (
    token: string,
    context: AuthenticationContext,
  ): Promise<SecurityPrincipal> => {
    const tokenFailure = validateTokenShape(token);
    if (tokenFailure) {
      await emit({
        event: 'security.authentication',
        outcome: 'denied',
        ...context,
        reason: tokenFailure,
      });
      throw new AuthenticationRequiredError(tokenFailure);
    }

    let candidate: SecurityPrincipal | null;
    try {
      candidate = await options.authenticate({ ...context, token });
    } catch (cause) {
      await emit({
        event: 'security.authentication',
        outcome: 'error',
        ...context,
        reason: 'provider-error',
      });
      throw new AuthenticationUnavailableError({ cause });
    }

    if (candidate === null) {
      await emit({
        event: 'security.authentication',
        outcome: 'denied',
        ...context,
        reason: 'invalid-token',
      });
      throw new AuthenticationRequiredError('invalid-token');
    }

    const validated = SecurityPrincipalSchema.safeParse(candidate);
    if (!validated.success) {
      await emit({
        event: 'security.authentication',
        outcome: 'denied',
        ...context,
        reason: 'invalid-principal',
      });
      throw new AuthenticationRequiredError('invalid-principal');
    }

    await emit({
      event: 'security.authentication',
      outcome: 'allowed',
      ...context,
      principalId: validated.data.id,
    });
    return validated.data;
  };

  return {
    authenticateToken,
    async authenticateBearer(header, context) {
      const parsed = parseBearerAuthorizationHeader(header);
      if (!parsed.ok) {
        await emit({
          event: 'security.authentication',
          outcome: 'denied',
          ...context,
          reason: parsed.reason,
        });
        throw new AuthenticationRequiredError(parsed.reason);
      }

      return await authenticateToken(parsed.token, context);
    },

    async requireCapability(principal, capability, context) {
      if (!hasKnowledgeCapability(principal, capability)) {
        await emit({
          event: 'security.authorization',
          outcome: 'denied',
          ...context,
          principalId: principal.id,
          capability,
          reason: 'missing-capability',
        });
        throw new AuthorizationDeniedError(principal.id, capability);
      }

      await emit({
        event: 'security.authorization',
        outcome: 'allowed',
        ...context,
        principalId: principal.id,
        capability,
      });
    },
  };
}
