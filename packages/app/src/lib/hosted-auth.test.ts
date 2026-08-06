import type { Auth0ClientOptions, RedirectLoginResult, User } from '@auth0/auth0-spa-js';
import { parseCollaborationCredential } from '@inkeep/open-knowledge-core';
import { afterEach, describe, expect, test, vi } from 'vitest';
import {
  configureHostedAuthentication,
  createHostedAuthSession,
  getHostedAccessTokenSupplier,
  HostedAuthConfigurationError,
  HostedAuthenticationRequiredError,
  resetHostedAuthenticationForTests,
  resolveHocuspocusAuthToken,
  resolveHostedAuthConfig,
} from './hosted-auth';

const createAuth0ClientMock = vi.hoisted(() => vi.fn());
vi.mock('@auth0/auth0-spa-js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@auth0/auth0-spa-js')>()),
  createAuth0Client: createAuth0ClientMock,
}));

function browser(search = '', path = '/docs/start', hash = '#intro') {
  const replacements: string[] = [];
  return {
    value: {
      location: { origin: 'https://knowledge.example', pathname: path, search, hash },
      replaceHistory: (next: string) => replacements.push(next),
    },
    replacements,
  };
}

function fakeClient(input: {
  authenticated?: boolean;
  user?: User;
  callback?: RedirectLoginResult<{ returnTo?: unknown }>;
}) {
  return {
    getTokenSilently: vi.fn(async () => 'access-token'),
    getUser: vi.fn(async () => input.user),
    handleRedirectCallback: vi.fn(async () => input.callback ?? { appState: {} }),
    isAuthenticated: vi.fn(async () => input.authenticated ?? false),
    loginWithRedirect: vi.fn(async () => undefined),
    logout: vi.fn(async () => undefined),
  };
}

const CONFIG = {
  domain: 'identity.example',
  clientId: 'browser-client',
  audience: 'https://knowledge.example/api',
};

afterEach(() => {
  createAuth0ClientMock.mockReset();
  resetHostedAuthenticationForTests();
});

describe('resolveHostedAuthConfig', () => {
  test('preserves local mode only when all hosted values are absent', () => {
    expect(resolveHostedAuthConfig({})).toBeNull();
    expect(() => resolveHostedAuthConfig({ VITE_OK_AUTH0_DOMAIN: 'identity.example' })).toThrow(
      HostedAuthConfigurationError,
    );
    expect(() => resolveHostedAuthConfig({ VITE_OK_AUTH0_CLIENT_ID: 'browser-client' })).toThrow(
      HostedAuthConfigurationError,
    );
    expect(() =>
      resolveHostedAuthConfig({ VITE_OK_AUTH0_AUDIENCE: 'https://knowledge.example/api' }),
    ).toThrow(HostedAuthConfigurationError);
    expect(() =>
      resolveHostedAuthConfig({
        VITE_OK_AUTH0_DOMAIN: ' ',
        VITE_OK_AUTH0_CLIENT_ID: 'browser-client',
        VITE_OK_AUTH0_AUDIENCE: 'audience',
      }),
    ).toThrow('all required');
    expect(() =>
      resolveHostedAuthConfig({
        VITE_OK_AUTH0_DOMAIN: 'identity.example',
        VITE_OK_AUTH0_CLIENT_ID: ' ',
        VITE_OK_AUTH0_AUDIENCE: 'audience',
      }),
    ).toThrow('all required');
    expect(() =>
      resolveHostedAuthConfig({
        VITE_OK_AUTH0_DOMAIN: 'identity.example',
        VITE_OK_AUTH0_CLIENT_ID: 'browser-client',
        VITE_OK_AUTH0_AUDIENCE: ' ',
      }),
    ).toThrow('all required');
  });

  test('normalizes a trusted Auth0 host and trims identifiers', () => {
    expect(
      resolveHostedAuthConfig({
        VITE_OK_AUTH0_DOMAIN: ' identity.example ',
        VITE_OK_AUTH0_CLIENT_ID: ' browser-client ',
        VITE_OK_AUTH0_AUDIENCE: ' audience ',
      }),
    ).toEqual({ domain: 'identity.example', clientId: 'browser-client', audience: 'audience' });
    expect(
      resolveHostedAuthConfig({
        VITE_OK_AUTH0_DOMAIN: 'https://identity.example/',
        VITE_OK_AUTH0_CLIENT_ID: 'browser-client',
        VITE_OK_AUTH0_AUDIENCE: 'audience',
      }),
    ).toMatchObject({ domain: 'identity.example' });
  });

  test('rejects domains with an unsafe transport or URL components', () => {
    const resolve = (domain: string) =>
      resolveHostedAuthConfig({
        VITE_OK_AUTH0_DOMAIN: domain,
        VITE_OK_AUTH0_CLIENT_ID: 'browser-client',
        VITE_OK_AUTH0_AUDIENCE: 'audience',
      });
    expect(() => resolve('http://identity.example')).toThrow('credential-free HTTPS host');
    expect(() => resolve('https://user:pass@identity.example')).toThrow(
      'credential-free HTTPS host',
    );
    expect(() => resolve('https://identity.example/path')).toThrow('credential-free HTTPS host');
    expect(() => resolve('https://identity.example?tenant=one')).toThrow(
      'credential-free HTTPS host',
    );
    expect(() => resolve('https://identity.example#fragment')).toThrow(
      'credential-free HTTPS host',
    );
    expect(() => resolve('https://identity.example:444')).toThrow('credential-free HTTPS host');
  });
});

describe('createHostedAuthSession', () => {
  test('creates the production Auth0 client without persistent refresh-token storage', async () => {
    const client = fakeClient({ authenticated: false });
    createAuth0ClientMock.mockResolvedValue(client);
    const session = createHostedAuthSession(CONFIG, browser().value);

    await expect(session.initialize()).resolves.toEqual({ status: 'unauthenticated' });
    expect(createAuth0ClientMock).toHaveBeenCalledWith({
      domain: CONFIG.domain,
      clientId: CONFIG.clientId,
      authorizationParams: {
        audience: CONFIG.audience,
        redirect_uri: 'https://knowledge.example',
      },
      cacheLocation: 'memory',
      useRefreshTokens: false,
      refreshTokenMode: 'offline',
    });
  });

  test('initializes an authenticated user once and supplies refreshed access tokens', async () => {
    const client = fakeClient({
      authenticated: true,
      user: {
        sub: 'auth0|employee',
        name: 'Ada Employee',
        picture: 'https://images.example/a.png',
      },
    });
    const createClient = vi.fn(async (_options: Auth0ClientOptions) => client);
    const session = createHostedAuthSession(CONFIG, browser().value, createClient as never);

    const first = session.initialize();
    const second = session.initialize();
    await expect(first).resolves.toEqual({
      status: 'authenticated',
      user: {
        subject: 'auth0|employee',
        displayName: 'Ada Employee',
        pictureUrl: 'https://images.example/a.png',
      },
    });
    await expect(second).resolves.toEqual(await first);
    await expect(session.getAccessToken()).resolves.toBe('access-token');

    expect(createClient).toHaveBeenCalledOnce();
    expect(createClient).toHaveBeenCalledWith({
      domain: CONFIG.domain,
      clientId: CONFIG.clientId,
      authorizationParams: {
        audience: CONFIG.audience,
        redirect_uri: 'https://knowledge.example',
      },
      cacheLocation: 'memory',
      useRefreshTokens: false,
    });
    expect(client.isAuthenticated).toHaveBeenCalledOnce();
    expect(client.getTokenSilently).toHaveBeenCalledOnce();
  });

  test('handles the Auth0 callback and restores only a safe relative path', async () => {
    const safeBrowser = browser('?code=one&state=two');
    const safeClient = fakeClient({
      authenticated: true,
      user: { sub: 'auth0|employee' },
      callback: { appState: { returnTo: '/restored?tab=one#section' } },
    });
    const safeSession = createHostedAuthSession(
      CONFIG,
      safeBrowser.value,
      (async () => safeClient) as never,
    );
    await safeSession.initialize();
    expect(safeClient.handleRedirectCallback).toHaveBeenCalledOnce();
    expect(safeBrowser.replacements).toEqual(['/restored?tab=one#section']);

    const unsafeBrowser = browser('?error=access_denied&state=two');
    const unsafeClient = fakeClient({
      authenticated: false,
      callback: { appState: { returnTo: '//attacker.example' } },
    });
    const unsafeSession = createHostedAuthSession(
      CONFIG,
      unsafeBrowser.value,
      (async () => unsafeClient) as never,
    );
    await unsafeSession.initialize();
    expect(unsafeBrowser.replacements).toEqual(['/']);
  });

  test('returns unauthenticated for an absent or unusable user', async () => {
    const unauthenticated = createHostedAuthSession(CONFIG, browser().value, (async () =>
      fakeClient({ authenticated: false })) as never);
    await expect(unauthenticated.initialize()).resolves.toEqual({ status: 'unauthenticated' });
    await expect(unauthenticated.getAccessToken()).rejects.toBeInstanceOf(
      HostedAuthenticationRequiredError,
    );

    const missingSubject = createHostedAuthSession(CONFIG, browser().value, (async () =>
      fakeClient({ authenticated: true, user: { name: 'No subject' } })) as never);
    await expect(missingSubject.initialize()).resolves.toEqual({ status: 'unauthenticated' });
  });

  test('bounds optional user presentation claims', async () => {
    const client = fakeClient({
      authenticated: true,
      user: { sub: 'auth0|employee', name: 'n'.repeat(257), picture: 42 as never },
    });
    const session = createHostedAuthSession(CONFIG, browser().value, (async () => client) as never);
    await expect(session.initialize()).resolves.toEqual({
      status: 'authenticated',
      user: { subject: 'auth0|employee' },
    });

    const emptyName = createHostedAuthSession(CONFIG, browser().value, (async () =>
      fakeClient({ authenticated: true, user: { sub: 'auth0|two', name: '' } })) as never);
    await expect(emptyName.initialize()).resolves.toMatchObject({
      user: { subject: 'auth0|two' },
    });

    const unsafePictures = [
      'http://images.example/a.png',
      'https://user:pass@images.example/a.png',
      'not-a-url',
      `https://images.example/${'x'.repeat(2_048)}`,
    ];
    for (const picture of unsafePictures) {
      const unsafePicture = createHostedAuthSession(CONFIG, browser().value, (async () =>
        fakeClient({ authenticated: true, user: { sub: 'auth0|three', picture } })) as never);
      await expect(unsafePicture.initialize()).resolves.toEqual({
        status: 'authenticated',
        user: { subject: 'auth0|three' },
      });
    }
  });

  test('starts redirect login and logout with bounded same-origin return locations', async () => {
    const testBrowser = browser('?view=graph', '/folder/page', '#heading');
    const client = fakeClient({ authenticated: false });
    const session = createHostedAuthSession(
      CONFIG,
      testBrowser.value,
      (async () => client) as never,
    );

    await session.login();
    await session.logout();

    expect(client.loginWithRedirect).toHaveBeenCalledWith({
      appState: { returnTo: '/folder/page?view=graph#heading' },
      authorizationParams: { redirect_uri: 'https://knowledge.example' },
    });
    expect(client.logout).toHaveBeenCalledWith({
      logoutParams: { returnTo: 'https://knowledge.example' },
    });
  });
});

describe('configureHostedAuthentication', () => {
  test('installs one shared access-token supplier only in hosted mode', async () => {
    expect(configureHostedAuthentication({}, browser().value, vi.fn() as never)).toBeNull();
    expect(getHostedAccessTokenSupplier()).toBeUndefined();
    expect(resolveHocuspocusAuthToken()).toBeUndefined();
    expect(resolveHocuspocusAuthToken('local-token')).toBe('local-token');

    const client = fakeClient({ authenticated: true, user: { sub: 'auth0|employee' } });
    const createClient = vi.fn(async () => client);
    const environment = {
      VITE_OK_AUTH0_DOMAIN: CONFIG.domain,
      VITE_OK_AUTH0_CLIENT_ID: CONFIG.clientId,
      VITE_OK_AUTH0_AUDIENCE: CONFIG.audience,
    };
    const first = configureHostedAuthentication(
      environment,
      browser().value,
      createClient as never,
    );
    const second = configureHostedAuthentication(
      environment,
      browser().value,
      createClient as never,
    );

    expect(second).toBe(first);
    await first?.initialize();
    await expect(getHostedAccessTokenSupplier()?.()).resolves.toBe('access-token');
    const hocuspocusToken = resolveHocuspocusAuthToken('local-token');
    expect(hocuspocusToken).toBeTypeOf('function');
    const withSync = await (hocuspocusToken as () => Promise<string>)();
    expect(parseCollaborationCredential(withSync)).toEqual({
      kind: 'envelope',
      bearerToken: 'access-token',
      syncToken: 'local-token',
    });

    const bearerOnly = resolveHocuspocusAuthToken();
    expect(bearerOnly).toBeTypeOf('function');
    expect(parseCollaborationCredential(await (bearerOnly as () => Promise<string>)())).toEqual({
      kind: 'envelope',
      bearerToken: 'access-token',
    });
    expect(createClient).toHaveBeenCalledOnce();
  });
});
