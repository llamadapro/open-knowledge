import { createLocalJWKSet, exportJWK, generateKeyPair, type JWTVerifyGetKey, SignJWT } from 'jose';
import { beforeAll, describe, expect, test, vi } from 'vitest';
import {
  Auth0ConfigurationError,
  resolveAuth0AuthorizationFromEnvironment,
} from './auth0-environment.ts';

const ISSUER = 'https://identity.example/';
const AUDIENCE = 'https://knowledge.example/api';
let privateKey: CryptoKey;
let keySet: JWTVerifyGetKey;

beforeAll(async () => {
  const pair = await generateKeyPair('RS256', { extractable: true });
  privateKey = pair.privateKey;
  const publicJwk = await exportJWK(pair.publicKey);
  keySet = createLocalJWKSet({ keys: [{ ...publicJwk, kid: 'test-key', alg: 'RS256' }] });
});

async function token(payload: Record<string, unknown> = {}): Promise<string> {
  return await new SignJWT(payload)
    .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setSubject('auth0|employee')
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(privateKey);
}

describe('resolveAuth0AuthorizationFromEnvironment', () => {
  test('preserves local mode only when the hosted configuration is entirely absent', () => {
    expect(resolveAuth0AuthorizationFromEnvironment({})).toBeUndefined();
    expect(() =>
      resolveAuth0AuthorizationFromEnvironment({
        OK_AUTH0_ISSUER: ISSUER,
        OK_AUTH0_AUDIENCE: AUDIENCE,
      }),
    ).not.toThrow();
    expect(() => resolveAuth0AuthorizationFromEnvironment({ OK_AUTH0_ISSUER: ISSUER })).toThrow(
      Auth0ConfigurationError,
    );
    expect(() => resolveAuth0AuthorizationFromEnvironment({ OK_AUTH0_AUDIENCE: AUDIENCE })).toThrow(
      Auth0ConfigurationError,
    );
    expect(() =>
      resolveAuth0AuthorizationFromEnvironment({ OK_AUTH0_MACHINE_PRINCIPALS_JSON: '{}' }),
    ).toThrow(Auth0ConfigurationError);
    expect(() =>
      resolveAuth0AuthorizationFromEnvironment({
        OK_AUTH0_ISSUER: ' ',
        OK_AUTH0_AUDIENCE: AUDIENCE,
      }),
    ).toThrow('both required');
    expect(() =>
      resolveAuth0AuthorizationFromEnvironment({
        OK_AUTH0_ISSUER: ISSUER,
        OK_AUTH0_AUDIENCE: ' ',
      }),
    ).toThrow('both required');
  });

  test('builds one authorization service and emits bounded audit events', async () => {
    const audit = vi.fn();
    const service = resolveAuth0AuthorizationFromEnvironment(
      { OK_AUTH0_ISSUER: ISSUER, OK_AUTH0_AUDIENCE: AUDIENCE },
      { keySet, audit },
    );
    const context = { transport: 'http' as const, resource: '/api/documents' };
    const principal = await service?.authenticateBearer(
      `Bearer ${await token({ permissions: ['knowledge.read'] })}`,
      context,
    );

    expect(principal).toMatchObject({ kind: 'human', capabilities: ['knowledge.read'] });
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'security.authentication',
        outcome: 'allowed',
        principalId: principal?.id,
      }),
    );
  });

  test('parses explicit machine principals and accepts an empty machine map', async () => {
    const machineService = resolveAuth0AuthorizationFromEnvironment(
      {
        OK_AUTH0_ISSUER: ISSUER,
        OK_AUTH0_AUDIENCE: AUDIENCE,
        OK_AUTH0_MACHINE_PRINCIPALS_JSON: JSON.stringify({
          'agent-client': { id: 'agent:knowledge:prod', kind: 'agent' },
        }),
      },
      { keySet },
    );
    const machineToken = await new SignJWT({
      gty: 'client-credentials',
      client_id: 'agent-client',
      permissions: ['knowledge.read'],
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setSubject('agent-client@clients')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);

    await expect(
      machineService?.authenticateBearer(`Bearer ${machineToken}`, {
        transport: 'mcp',
        resource: 'initialize',
      }),
    ).resolves.toMatchObject({ id: 'agent:knowledge:prod' });

    expect(() =>
      resolveAuth0AuthorizationFromEnvironment(
        {
          OK_AUTH0_ISSUER: ISSUER,
          OK_AUTH0_AUDIENCE: AUDIENCE,
          OK_AUTH0_MACHINE_PRINCIPALS_JSON: ' ',
        },
        { keySet },
      ),
    ).not.toThrow();
  });

  test('rejects malformed, unbounded, and non-object machine configuration', () => {
    const resolve = (raw: string) =>
      resolveAuth0AuthorizationFromEnvironment({
        OK_AUTH0_ISSUER: ISSUER,
        OK_AUTH0_AUDIENCE: AUDIENCE,
        OK_AUTH0_MACHINE_PRINCIPALS_JSON: raw,
      });

    expect(() => resolve('{')).toThrow('must be valid JSON');
    expect(() => resolve('null')).toThrow('must be an object');
    expect(() => resolve('[]')).toThrow('must be an object');
    expect(() => resolve('"string"')).toThrow('must be an object');
    expect(() => resolve('x'.repeat(64 * 1024 + 1))).toThrow('too large');
  });
});
