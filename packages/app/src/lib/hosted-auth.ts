import {
  type Auth0Client,
  type Auth0ClientOptions,
  createAuth0Client,
  type RedirectLoginResult,
  type User,
} from '@auth0/auth0-spa-js';
import { createCollaborationCredential } from '@inkeep/open-knowledge-core';

export interface HostedAuthEnvironment {
  VITE_OK_AUTH0_DOMAIN?: string;
  VITE_OK_AUTH0_CLIENT_ID?: string;
  VITE_OK_AUTH0_AUDIENCE?: string;
}

export interface HostedAuthConfig {
  domain: string;
  clientId: string;
  audience: string;
}

export interface HostedAuthUser {
  subject: string;
  displayName?: string;
  pictureUrl?: string;
}

export type HostedAuthState =
  | { status: 'authenticated'; user: HostedAuthUser }
  | { status: 'unauthenticated' };

export class HostedAuthConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'HostedAuthConfigurationError';
  }
}

export class HostedAuthenticationRequiredError extends Error {
  constructor() {
    super('Hosted authentication required.');
    this.name = 'HostedAuthenticationRequiredError';
  }
}

interface HostedAuthClient
  extends Pick<
    Auth0Client,
    | 'getTokenSilently'
    | 'getUser'
    | 'handleRedirectCallback'
    | 'isAuthenticated'
    | 'loginWithRedirect'
    | 'logout'
  > {}

interface BrowserLocation {
  origin: string;
  pathname: string;
  search: string;
  hash: string;
}

interface HostedAuthBrowser {
  location: BrowserLocation;
  replaceHistory: (path: string) => void;
}

type Auth0ClientFactory = (options: Auth0ClientOptions) => Promise<HostedAuthClient>;

const defaultAuth0ClientFactory: Auth0ClientFactory = async (options) =>
  await createAuth0Client({ ...options, refreshTokenMode: 'offline' });

function normalizeDomain(value: string): string {
  const trimmed = value.trim();
  const withScheme = trimmed.includes('://') ? trimmed : `https://${trimmed}`;
  const domain = new URL(withScheme);
  if (
    domain.protocol !== 'https:' ||
    domain.username !== '' ||
    domain.password !== '' ||
    (domain.pathname !== '' && domain.pathname !== '/') ||
    domain.search !== '' ||
    domain.hash !== '' ||
    domain.port !== ''
  ) {
    throw new HostedAuthConfigurationError('Auth0 domain must be a credential-free HTTPS host.');
  }
  return domain.hostname;
}

export function resolveHostedAuthConfig(
  environment: HostedAuthEnvironment,
): HostedAuthConfig | null {
  const domain = environment.VITE_OK_AUTH0_DOMAIN;
  const clientId = environment.VITE_OK_AUTH0_CLIENT_ID;
  const audience = environment.VITE_OK_AUTH0_AUDIENCE;
  if (domain === undefined && clientId === undefined && audience === undefined) return null;
  if (!domain?.trim() || !clientId?.trim() || !audience?.trim()) {
    throw new HostedAuthConfigurationError(
      'VITE_OK_AUTH0_DOMAIN, VITE_OK_AUTH0_CLIENT_ID, and VITE_OK_AUTH0_AUDIENCE are all required in hosted mode.',
    );
  }
  return { domain: normalizeDomain(domain), clientId: clientId.trim(), audience: audience.trim() };
}

function hasAuthenticationCallback(search: string): boolean {
  const params = new URLSearchParams(search);
  return params.has('state') && (params.has('code') || params.has('error'));
}

function safeReturnPath(value: unknown): string | null {
  return typeof value === 'string' && value.startsWith('/') && !value.startsWith('//')
    ? value
    : null;
}

function currentRelativePath(location: BrowserLocation): string {
  return `${location.pathname}${location.search}${location.hash}`;
}

function mapUser(user: User | undefined): HostedAuthUser | null {
  if (!user?.sub) return null;
  const displayName =
    typeof user.name === 'string' && user.name.length > 0 && user.name.length <= 256
      ? user.name
      : undefined;
  const pictureUrl = safePictureUrl(user.picture);
  return {
    subject: user.sub,
    ...(displayName ? { displayName } : {}),
    ...(pictureUrl ? { pictureUrl } : {}),
  };
}

function safePictureUrl(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.length > 2_048) return undefined;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.username === '' && url.password === ''
      ? url.href
      : undefined;
  } catch {
    return undefined;
  }
}

export interface HostedAuthSession {
  initialize: () => Promise<HostedAuthState>;
  getAccessToken: () => Promise<string>;
  login: () => Promise<void>;
  logout: () => Promise<void>;
}

export function createHostedAuthSession(
  config: HostedAuthConfig,
  browser: HostedAuthBrowser,
  createClient: Auth0ClientFactory = defaultAuth0ClientFactory,
): HostedAuthSession {
  const redirectUri = browser.location.origin;
  const clientPromise = createClient({
    domain: config.domain,
    clientId: config.clientId,
    authorizationParams: { audience: config.audience, redirect_uri: redirectUri },
    cacheLocation: 'memory',
    useRefreshTokens: false,
  });
  let initialization: Promise<HostedAuthState> | null = null;

  const initializeOnce = async (): Promise<HostedAuthState> => {
    const client = await clientPromise;
    if (hasAuthenticationCallback(browser.location.search)) {
      const result = (await client.handleRedirectCallback()) as RedirectLoginResult<{
        returnTo?: unknown;
      }>;
      browser.replaceHistory(safeReturnPath(result.appState?.returnTo) ?? '/');
    }
    if (!(await client.isAuthenticated())) return { status: 'unauthenticated' };
    const user = mapUser(await client.getUser());
    return user ? { status: 'authenticated', user } : { status: 'unauthenticated' };
  };

  return {
    initialize() {
      initialization ??= initializeOnce();
      return initialization;
    },
    async getAccessToken() {
      initialization ??= initializeOnce();
      const state = await initialization;
      if (state.status !== 'authenticated') throw new HostedAuthenticationRequiredError();
      const client = await clientPromise;
      return await client.getTokenSilently();
    },
    async login() {
      const client = await clientPromise;
      await client.loginWithRedirect({
        appState: { returnTo: currentRelativePath(browser.location) },
        authorizationParams: { redirect_uri: redirectUri },
      });
    },
    async logout() {
      const client = await clientPromise;
      await client.logout({ logoutParams: { returnTo: redirectUri } });
    },
  };
}

let hostedAuthSession: HostedAuthSession | null = null;
let hostedAccessTokenSupplier: (() => Promise<string>) | undefined;

export function configureHostedAuthentication(
  environment: HostedAuthEnvironment,
  browser: HostedAuthBrowser,
  createClient: Auth0ClientFactory = defaultAuth0ClientFactory,
): HostedAuthSession | null {
  const config = resolveHostedAuthConfig(environment);
  if (config === null) return null;
  hostedAuthSession ??= createHostedAuthSession(config, browser, createClient);
  hostedAccessTokenSupplier ??= hostedAuthSession.getAccessToken;
  return hostedAuthSession;
}

export function getHostedAccessTokenSupplier(): (() => Promise<string>) | undefined {
  return hostedAccessTokenSupplier;
}

export function resolveHocuspocusAuthToken(
  localToken?: string,
): string | (() => Promise<string>) | undefined {
  const supplier = hostedAccessTokenSupplier;
  if (supplier === undefined) return localToken;
  return async () =>
    createCollaborationCredential({
      bearerToken: await supplier(),
      ...(localToken ? { syncToken: localToken } : {}),
    });
}

export function resetHostedAuthenticationForTests(): void {
  hostedAuthSession = null;
  hostedAccessTokenSupplier = undefined;
}
