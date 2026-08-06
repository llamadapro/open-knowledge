import { Trans } from '@lingui/react/macro';
import { type ReactNode, useEffect, useState } from 'react';
import { Button } from '@/components/ui/button';
import type { HostedAuthSession, HostedAuthState } from '@/lib/hosted-auth';

type BoundaryState = { status: 'loading' } | HostedAuthState | { status: 'error' };

interface HostedAuthBoundaryProps {
  children: ReactNode;
  reload: () => void;
  session: HostedAuthSession | null;
}

export function HostedAuthBoundary({ children, reload, session }: HostedAuthBoundaryProps) {
  const [state, setState] = useState<BoundaryState>(() =>
    session === null
      ? { status: 'authenticated', user: { subject: 'local' } }
      : { status: 'loading' },
  );

  useEffect(() => {
    if (session === null) return;
    let active = true;
    session.initialize().then(
      (next) => {
        if (active) setState(next);
      },
      (error: unknown) => {
        console.error('[HostedAuthBoundary] Auth0 initialization failed', error);
        if (active) setState({ status: 'error' });
      },
    );
    return () => {
      active = false;
    };
  }, [session]);

  if (session === null || state.status === 'authenticated') return children;

  if (state.status === 'loading') {
    return (
      <main
        aria-busy="true"
        aria-live="polite"
        className="flex h-screen items-center justify-center bg-background text-foreground"
      >
        <p className="text-sm text-muted-foreground">
          <Trans>Checking your company access...</Trans>
        </p>
      </main>
    );
  }

  return (
    <main className="flex h-screen items-center justify-center bg-background p-6 text-foreground">
      <section className="flex max-w-sm flex-col items-center gap-4 text-center">
        <div className="flex size-10 items-center justify-center rounded-lg bg-foreground font-mono font-semibold text-background">
          OK
        </div>
        <div className="space-y-1">
          <h1 className="text-xl font-semibold">
            {state.status === 'error' ? (
              <Trans>Sign-in is unavailable</Trans>
            ) : (
              <Trans>Sign in to OpenKnowledge</Trans>
            )}
          </h1>
          <p className="text-sm text-muted-foreground">
            {state.status === 'error' ? (
              <Trans>Reload the page or contact your administrator if the problem continues.</Trans>
            ) : (
              <Trans>Use your company account to access this knowledge base.</Trans>
            )}
          </p>
        </div>
        {state.status === 'error' ? (
          <Button type="button" variant="outline" onClick={reload}>
            <Trans>Reload</Trans>
          </Button>
        ) : (
          <Button type="button" onClick={() => void session.login()}>
            <Trans>Sign in</Trans>
          </Button>
        )}
      </section>
    </main>
  );
}
