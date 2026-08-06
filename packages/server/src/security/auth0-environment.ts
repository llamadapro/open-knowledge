import type { JWTVerifyGetKey } from 'jose';
import {
  type Auth0MachinePrincipal,
  createAuth0PrincipalAuthenticator,
} from './auth0-authenticator.ts';
import {
  type AuthorizationService,
  createAuthorizationService,
  type SecurityAuditSink,
} from './authorization.ts';

const MAX_MACHINE_PRINCIPALS_JSON_BYTES = 64 * 1024;

export interface Auth0Environment {
  OK_AUTH0_ISSUER?: string;
  OK_AUTH0_AUDIENCE?: string;
  OK_AUTH0_MACHINE_PRINCIPALS_JSON?: string;
}

export interface Auth0EnvironmentResolutionOptions {
  audit?: SecurityAuditSink;
  /** Injected only for deterministic tests or a trusted non-HTTP JWKS cache. */
  keySet?: JWTVerifyGetKey;
}

export class Auth0ConfigurationError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'Auth0ConfigurationError';
  }
}

function parseMachinePrincipals(raw: string | undefined): Record<string, Auth0MachinePrincipal> {
  if (raw === undefined || raw.trim() === '') return {};
  if (Buffer.byteLength(raw, 'utf8') > MAX_MACHINE_PRINCIPALS_JSON_BYTES) {
    throw new Auth0ConfigurationError('OK_AUTH0_MACHINE_PRINCIPALS_JSON is too large.');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (cause) {
    throw new Auth0ConfigurationError('OK_AUTH0_MACHINE_PRINCIPALS_JSON must be valid JSON.', {
      cause,
    });
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Auth0ConfigurationError(
      'OK_AUTH0_MACHINE_PRINCIPALS_JSON must be an object keyed by Auth0 client id.',
    );
  }
  return parsed as Record<string, Auth0MachinePrincipal>;
}

/**
 * Resolve optional hosted-server Auth0 configuration from environment values.
 * All variables absent preserves local single-user mode. Any partial hosted
 * configuration fails at startup rather than serving a half-protected process.
 */
export function resolveAuth0AuthorizationFromEnvironment(
  environment: Auth0Environment,
  options: Auth0EnvironmentResolutionOptions = {},
): AuthorizationService | undefined {
  const { OK_AUTH0_ISSUER: issuer, OK_AUTH0_AUDIENCE: audience } = environment;
  const machineJson = environment.OK_AUTH0_MACHINE_PRINCIPALS_JSON;
  if (issuer === undefined && audience === undefined && machineJson === undefined) return undefined;
  if (!issuer?.trim() || !audience?.trim()) {
    throw new Auth0ConfigurationError(
      'OK_AUTH0_ISSUER and OK_AUTH0_AUDIENCE are both required when Auth0 is configured.',
    );
  }

  const authenticate = createAuth0PrincipalAuthenticator({
    issuer,
    audience,
    machinePrincipals: parseMachinePrincipals(machineJson),
    ...(options.keySet ? { keySet: options.keySet } : {}),
  });
  return createAuthorizationService({ authenticate, audit: options.audit });
}
