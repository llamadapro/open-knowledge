import { z } from 'zod';

const COLLABORATION_CREDENTIAL_PREFIX = 'ok-auth-v1:';
const MAX_BEARER_TOKEN_BYTES = 8 * 1024;
const MAX_SYNC_TOKEN_BYTES = 16 * 1024;
const MAX_CREDENTIAL_BYTES = 24 * 1024;

const CollaborationCredentialEnvelopeSchema = z
  .object({
    bearerToken: z.string().min(1),
    syncToken: z.string().min(1).optional(),
  })
  .strict();

export interface CollaborationCredentialEnvelope {
  bearerToken: string;
  syncToken?: string;
}

export type ParsedCollaborationCredential =
  | { kind: 'raw'; token: string }
  | { kind: 'envelope'; bearerToken: string; syncToken?: string }
  | { kind: 'invalid'; reason: 'missing' | 'malformed' | 'too-large' };

function byteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function parseEnvelopeCredential(
  token: string,
): Exclude<ParsedCollaborationCredential, { kind: 'raw' }> {
  if (byteLength(token) > MAX_CREDENTIAL_BYTES) return { kind: 'invalid', reason: 'too-large' };

  let untrusted: unknown;
  try {
    untrusted = JSON.parse(token.slice(COLLABORATION_CREDENTIAL_PREFIX.length));
  } catch {
    return { kind: 'invalid', reason: 'malformed' };
  }
  const result = CollaborationCredentialEnvelopeSchema.safeParse(untrusted);
  if (!result.success) return { kind: 'invalid', reason: 'malformed' };
  if (
    byteLength(result.data.bearerToken) > MAX_BEARER_TOKEN_BYTES ||
    (result.data.syncToken !== undefined &&
      byteLength(result.data.syncToken) > MAX_SYNC_TOKEN_BYTES)
  ) {
    return { kind: 'invalid', reason: 'too-large' };
  }
  return { kind: 'envelope', ...result.data };
}

export function parseCollaborationCredential(
  token: string | null | undefined,
): ParsedCollaborationCredential {
  if (typeof token !== 'string' || token.length === 0) {
    return { kind: 'invalid', reason: 'missing' };
  }
  if (!token.startsWith(COLLABORATION_CREDENTIAL_PREFIX)) return { kind: 'raw', token };
  return parseEnvelopeCredential(token);
}

export function createCollaborationCredential(envelope: CollaborationCredentialEnvelope): string {
  const candidate = `${COLLABORATION_CREDENTIAL_PREFIX}${JSON.stringify(envelope)}`;
  const parsed = parseEnvelopeCredential(candidate);
  if (parsed.kind !== 'envelope') {
    throw new TypeError(`Invalid collaboration credential: ${parsed.reason}.`);
  }
  return candidate;
}
