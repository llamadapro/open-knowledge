import * as actualLinguiMacro from '@lingui/react/macro';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, describe, expect, test, vi } from 'vitest';
import type { HostedAuthSession } from '@/lib/hosted-auth';
import { HostedAuthBoundary } from './HostedAuthBoundary';

vi.doMock('@lingui/react/macro', () => ({
  ...actualLinguiMacro,
  Trans: ({ children }: { children: ReactNode }) => <>{children}</>,
}));

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function session(overrides: Partial<HostedAuthSession> = {}): HostedAuthSession {
  return {
    initialize: vi.fn(async () => ({ status: 'unauthenticated' })),
    getAccessToken: vi.fn(async () => 'token'),
    login: vi.fn(async () => undefined),
    logout: vi.fn(async () => undefined),
    ...overrides,
  };
}

const reload = () => {};

describe('HostedAuthBoundary', () => {
  test('leaves local and desktop mode unchanged', () => {
    render(
      <HostedAuthBoundary session={null} reload={reload}>
        <p>knowledge</p>
      </HostedAuthBoundary>,
    );
    expect(screen.getByText('knowledge')).toBeTruthy();
  });

  test('blocks the application until hosted authentication completes', async () => {
    let resolveState:
      | ((state: { status: 'authenticated'; user: { subject: string } }) => void)
      | null = null;
    const auth = session({
      initialize: vi.fn(
        () =>
          new Promise((resolve) => {
            resolveState = resolve;
          }),
      ),
    });
    render(
      <HostedAuthBoundary session={auth} reload={reload}>
        <p>knowledge</p>
      </HostedAuthBoundary>,
    );

    expect(screen.getByText('Checking your company access...')).toBeTruthy();
    expect(screen.queryByText('knowledge')).toBeNull();
    resolveState?.({ status: 'authenticated', user: { subject: 'auth0|employee' } });
    expect(await screen.findByText('knowledge')).toBeTruthy();
  });

  test('offers company login when there is no hosted session', async () => {
    const auth = session();
    render(
      <HostedAuthBoundary session={auth} reload={reload}>
        <p>knowledge</p>
      </HostedAuthBoundary>,
    );

    const signIn = await screen.findByRole('button', { name: 'Sign in' });
    fireEvent.click(signIn);
    expect(auth.login).toHaveBeenCalledOnce();
  });

  test('contains initialization failures without mounting the application', async () => {
    const error = new Error('identity provider unavailable');
    const reload = vi.fn();
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const auth = session({ initialize: vi.fn(async () => await Promise.reject(error)) });
    render(
      <HostedAuthBoundary session={auth} reload={reload}>
        <p>knowledge</p>
      </HostedAuthBoundary>,
    );

    expect(await screen.findByText('Sign-in is unavailable')).toBeTruthy();
    expect(screen.queryByText('knowledge')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Reload' }));
    expect(reload).toHaveBeenCalledOnce();
    expect(console.error).toHaveBeenCalledWith(
      '[HostedAuthBoundary] Auth0 initialization failed',
      error,
    );
  });

  test('does not update state after unmount', async () => {
    let reject: ((error: Error) => void) | null = null;
    const auth = session({
      initialize: vi.fn(
        () =>
          new Promise((_resolve, rejectPromise) => {
            reject = rejectPromise;
          }),
      ),
    });
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const rendered = render(
      <HostedAuthBoundary session={auth} reload={reload}>
        <p>knowledge</p>
      </HostedAuthBoundary>,
    );
    rendered.unmount();
    reject?.(new Error('late failure'));
    await waitFor(() => expect(console.error).toHaveBeenCalledOnce());
  });

  test('ignores successful initialization that completes after unmount', async () => {
    let resolve: ((state: { status: 'authenticated'; user: { subject: string } }) => void) | null =
      null;
    const auth = session({
      initialize: vi.fn(
        () =>
          new Promise((resolvePromise) => {
            resolve = resolvePromise;
          }),
      ),
    });
    const rendered = render(
      <HostedAuthBoundary session={auth} reload={reload}>
        <p>knowledge</p>
      </HostedAuthBoundary>,
    );
    rendered.unmount();
    resolve?.({ status: 'authenticated', user: { subject: 'auth0|employee' } });
    await Promise.resolve();
  });
});
