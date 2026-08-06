import type { SecurityPrincipal } from '@inkeep/open-knowledge-core';
import {
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  type JWTPayload,
  type JWTVerifyGetKey,
  SignJWT,
} from 'jose';
import { beforeAll, describe, expect, test } from 'vitest';
import {
  type Auth0AuthenticatorOptions,
  createAuth0PrincipalAuthenticator,
} from './auth0-authenticator.ts';

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

async function sign(payload: JWTPayload): Promise<string> {
  let token = new SignJWT(payload)
    .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setIssuedAt()
    .setExpirationTime('5m');
  if (payload.sub) token = token.setSubject(payload.sub);
  return await token.sign(privateKey);
}

function authenticator(options: Partial<Auth0AuthenticatorOptions> = {}) {
  return createAuth0PrincipalAuthenticator({
    issuer: ISSUER,
    audience: AUDIENCE,
    keySet,
    ...options,
  });
}

async function authenticate(payload: JWTPayload): Promise<SecurityPrincipal | null> {
  return await authenticator()({
    token: await sign(payload),
    transport: 'http',
    resource: '/api/documents',
  });
}

describe('createAuth0PrincipalAuthenticator', () => {
  test('maps a verified human token to a bounded provider-neutral principal', async () => {
    const principal = await authenticate({
      sub: 'auth0|employee-1',
      name: 'Ada Employee',
      permissions: [
        'knowledge.propose',
        'unknown.permission',
        'knowledge.read',
        'knowledge.read',
        42,
      ],
    });

    expect(principal).toEqual({
      id: expect.stringMatching(/^human:[A-Za-z0-9_-]{43}$/),
      kind: 'human',
      issuer: ISSUER,
      subject: 'auth0|employee-1',
      displayName: 'Ada Employee',
      capabilities: ['knowledge.read', 'knowledge.propose'],
    });
  });

  test('omits unusable names and permissions instead of leaking arbitrary claims', async () => {
    const nonString = await authenticate({ sub: 'auth0|one', name: 42, permissions: 'read' });
    const empty = await authenticate({ sub: 'auth0|two', name: '' });
    const tooLong = await authenticate({ sub: 'auth0|three', name: 'n'.repeat(257) });

    expect(nonString).not.toHaveProperty('displayName');
    expect(nonString?.capabilities).toEqual([]);
    expect(empty).not.toHaveProperty('displayName');
    expect(tooLong).not.toHaveProperty('displayName');
  });

  test('maps configured client-credentials callers by client_id, azp, or Auth0 subject', async () => {
    const auth = authenticator({
      machinePrincipals: {
        'agent-client': { id: 'agent:research:prod', kind: 'agent', displayName: 'Research' },
        'service-client': { id: 'service:indexer:prod', kind: 'service' },
        'subject-client': { id: 'agent:subject:prod', kind: 'agent' },
      },
    });
    const run = async (payload: JWTPayload) =>
      await auth({ token: await sign(payload), transport: 'mcp', resource: 'initialize' });

    await expect(
      run({
        sub: 'ignored@clients',
        gty: 'client-credentials',
        client_id: 'agent-client',
        azp: 'service-client',
        permissions: ['knowledge.read'],
      }),
    ).resolves.toMatchObject({ id: 'agent:research:prod', subject: 'ignored@clients' });
    await expect(
      run({
        sub: 'ignored@clients',
        gty: 'client-credentials',
        azp: 'service-client',
      }),
    ).resolves.toMatchObject({ id: 'service:indexer:prod' });
    await expect(run({ sub: 'subject-client@clients' })).resolves.toMatchObject({
      id: 'agent:subject:prod',
    });
  });

  test('rejects unknown or unidentifiable client-credentials callers', async () => {
    const auth = authenticator({ machinePrincipals: {} });
    const run = async (payload: JWTPayload) =>
      await auth({ token: await sign(payload), transport: 'mcp', resource: 'initialize' });

    await expect(run({ sub: 'unknown@clients', gty: 'client-credentials' })).resolves.toBeNull();
    await expect(run({ sub: 'invalid-subject', gty: 'client-credentials' })).resolves.toBeNull();
    await expect(run({ sub: '@clients' })).resolves.toBeNull();
  });

  test('does not classify an ordinary authorized-party claim as a machine', async () => {
    await expect(
      authenticate({ sub: 'auth0|human', azp: 'browser-client' }),
    ).resolves.toMatchObject({
      kind: 'human',
    });
  });

  test('rejects missing, oversized, malformed, expired, and wrong-audience credentials', async () => {
    await expect(authenticate({})).resolves.toBeNull();
    await expect(authenticate({ sub: 's'.repeat(513) })).resolves.toBeNull();

    const auth = authenticator();
    const context = { transport: 'websocket' as const, resource: 'document:readme' };
    await expect(auth({ token: 'not-a-jwt', ...context })).resolves.toBeNull();

    const expired = await new SignJWT({ permissions: ['knowledge.read'] })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setSubject('auth0|expired')
      .setExpirationTime(1)
      .sign(privateKey);
    await expect(auth({ token: expired, ...context })).resolves.toBeNull();

    const wrongAudience = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
      .setIssuer(ISSUER)
      .setAudience('https://wrong.example/api')
      .setSubject('auth0|wrong-audience')
      .setExpirationTime('5m')
      .sign(privateKey);
    await expect(auth({ token: wrongAudience, ...context })).resolves.toBeNull();
  });

  test('propagates identity-provider availability failures', async () => {
    const offlineKeySet: JWTVerifyGetKey = async () => {
      throw new TypeError('identity provider offline');
    };
    const auth = authenticator({ keySet: offlineKeySet });

    await expect(
      auth({
        token: await sign({ sub: 'auth0|employee' }),
        transport: 'http',
        resource: '/api/documents',
      }),
    ).rejects.toThrow('identity provider offline');
  });

  test('normalizes a trusted issuer and validates startup configuration', async () => {
    const normalized = createAuth0PrincipalAuthenticator({
      issuer: 'https://identity.example',
      audience: AUDIENCE,
      keySet,
    });
    await expect(
      normalized({
        token: await sign({ sub: 'auth0|employee' }),
        transport: 'http',
        resource: '/api/documents',
      }),
    ).resolves.toMatchObject({ issuer: ISSUER });

    expect(() =>
      createAuth0PrincipalAuthenticator({
        issuer: 'https://identity.example/tenant',
        audience: AUDIENCE,
        keySet,
      }),
    ).not.toThrow();
    expect(() =>
      createAuth0PrincipalAuthenticator({ issuer: ISSUER, audience: AUDIENCE }),
    ).not.toThrow();

    expect(() => authenticator({ issuer: 'http://identity.example' })).toThrow(
      'credential-free HTTPS URL',
    );
    expect(() => authenticator({ issuer: 'https://user:pass@identity.example' })).toThrow(
      'credential-free HTTPS URL',
    );
    expect(() => authenticator({ issuer: 'https://identity.example?tenant=one' })).toThrow(
      'credential-free HTTPS URL',
    );
    expect(() => authenticator({ issuer: 'https://identity.example#fragment' })).toThrow(
      'credential-free HTTPS URL',
    );
    expect(() => authenticator({ issuer: `https://identity.example/${'x'.repeat(2048)}` })).toThrow(
      'issuer URL is too long',
    );
    expect(() => authenticator({ audience: '   ' })).toThrow('audience must not be empty');
    expect(() =>
      authenticator({ machinePrincipals: { ' ': { id: 'agent:a', kind: 'agent' } } }),
    ).toThrow('client id must not be empty');
    expect(() =>
      authenticator({
        machinePrincipals: {
          invalid: { id: 'human:not-a-machine', kind: 'human' } as never,
        },
      }),
    ).toThrow('Invalid Auth0 machine principal configuration');
    expect(() =>
      authenticator({
        machinePrincipals: {
          invalid: { id: 'invalid-id', kind: 'agent' },
        },
      }),
    ).toThrow('Invalid Auth0 machine principal configuration');
  });
});
