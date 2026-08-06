import { createServer } from 'node:http';
import type { KnowledgeRuntimeScope } from '@inkeep/open-knowledge-core';
import { describe, expect, test, vi } from 'vitest';
import { parseProblem, rawRequest } from '../composition-rig.test-helper.ts';
import { listenOnLoopback } from '../loopback-rig-test-helpers.ts';
import {
  type AuthorizationService,
  createAuthorizationService,
} from '../security/authorization.ts';
import { type ApiRouteTable, createApiRequestPipeline } from './api-pipeline.ts';
import { createHttpApp, type NativeApiHandle } from './http-app.ts';
import { getSecurityPrincipal } from './security-context.ts';

/**
 * Gate parity for natively-mounted `/api/*` routes. The composition suite
 * (`api-admission-composition.test.ts`) pins the admission gates as the
 * LEGACY dispatch applies them; this suite pins the same wire behavior for
 * routes mounted ABOVE the strangler catch-all through `NativeApiHandle` —
 * the exact bypass the native mount exists to close. A synthetic route table
 * keeps the pins independent of any real route group's handler behavior.
 */

const fakeLog = {
  error: () => {},
  warn: () => {},
  info: () => {},
  debug: () => {},
  child: () => fakeLog,
} as never;

/** The exact preflight header list the legacy dispatch reflects — byte-pinned. */
const EXPECTED_ALLOW_HEADERS =
  'Content-Type, Authorization, traceparent, tracestate, baggage, x-request-id, x-ok-client-protocol, x-ok-client-runtime, x-ok-client-kind';

interface NativeRig {
  port: number;
  baseUrl: string;
  legacyCalls: string[];
  principalIds: Array<string | undefined>;
  close: () => Promise<void>;
}

async function bootNativeRig(
  opts: {
    authorization?: AuthorizationService;
    ephemeral?: boolean;
    runtimeScope?: KnowledgeRuntimeScope;
    workspaceAudit?: Parameters<typeof createApiRequestPipeline>[0]['workspaceAudit'];
  } = {},
): Promise<NativeRig> {
  const legacyCalls: string[] = [];
  const principalIds: Array<string | undefined> = [];
  const table: ApiRouteTable = {
    resolve(pathname) {
      if (pathname === '/api/native-ping' || pathname === '/api/native-mutating') {
        return {
          template: pathname,
          dispatch: async (req, res) => {
            principalIds.push(getSecurityPrincipal(req)?.id);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ pong: true }));
          },
        };
      }
      if (pathname === '/api/native-throw') {
        return {
          template: pathname,
          dispatch: async () => {
            throw new Error('handler boom');
          },
        };
      }
      // Owned prefix with no handler — the pipeline's 404 must close it.
      if (pathname === '/api/native-empty') {
        return { template: '/api/native-empty' };
      }
      return null;
    },
    isMutating: (pathname) => pathname === '/api/native-mutating',
  };
  const nativeApi: NativeApiHandle = {
    paths: [
      '/api/native-ping',
      '/api/native-mutating',
      '/api/native-throw',
      '/api/native-empty',
      // Claimed by the router but declined by the table — must fall through
      // to the legacy dispatch.
      '/api/native-declined',
    ],
    dispatch: createApiRequestPipeline({
      log: fakeLog,
      ephemeral: opts.ephemeral,
      authorization: opts.authorization,
      runtimeScope: opts.runtimeScope,
      workspaceAudit: opts.workspaceAudit,
      table,
    }),
  };
  const { requestListener } = createHttpApp({
    nativeApi,
    legacyDispatch: (req, res) => {
      legacyCalls.push(req.url ?? '');
      res.writeHead(299, { 'Content-Type': 'text/plain' });
      res.end('legacy');
    },
    log: fakeLog,
  });
  const server = createServer(requestListener);
  const { port, baseUrl } = await listenOnLoopback(server);
  return {
    port,
    baseUrl,
    legacyCalls,
    principalIds,
    close: () =>
      new Promise<void>((resolvePromise, reject) => {
        server.close((err) => (err ? reject(err) : resolvePromise()));
      }),
  };
}

function readerAuthorization() {
  return createAuthorizationService({
    authenticate: async ({ token }) =>
      token === 'reader-token'
        ? {
            id: 'human:reader',
            kind: 'human',
            issuer: 'test',
            subject: 'reader',
            capabilities: ['knowledge.read'],
          }
        : null,
  });
}

function contributorAuthorization() {
  return createAuthorizationService({
    authenticate: async ({ token }) =>
      token === 'contributor-token'
        ? {
            id: 'human:contributor',
            kind: 'human',
            issuer: 'test',
            subject: 'contributor',
            capabilities: ['knowledge.read', 'knowledge.propose'],
          }
        : null,
  });
}

describe('natively-mounted /api routes run the shared admission pipeline', () => {
  test('shared mode rejects anonymous API reads before dispatch', async () => {
    const rig = await bootNativeRig({ authorization: readerAuthorization() });
    try {
      const response = await fetch(`${rig.baseUrl}/api/native-ping`);
      expect(response.status).toBe(401);
      expect(response.headers.get('www-authenticate')).toBe('Bearer');
      expect(await response.json()).toMatchObject({
        type: 'urn:ok:error:authentication-required',
        title: 'Authentication required.',
      });
      expect(rig.principalIds).toEqual([]);
    } finally {
      await rig.close();
    }
  });

  test('shared mode propagates the authenticated principal to read handlers', async () => {
    const rig = await bootNativeRig({ authorization: readerAuthorization() });
    try {
      const response = await fetch(`${rig.baseUrl}/api/native-ping`, {
        headers: { authorization: 'Bearer reader-token' },
      });
      expect(response.status).toBe(200);
      expect(rig.principalIds).toEqual(['human:reader']);
    } finally {
      await rig.close();
    }
  });

  test('shared mode requires proposal capability for mutating routes', async () => {
    const rig = await bootNativeRig({ authorization: readerAuthorization() });
    try {
      const response = await fetch(`${rig.baseUrl}/api/native-mutating`, {
        headers: { authorization: 'Bearer reader-token' },
      });
      expect(response.status).toBe(403);
      expect(await response.json()).toMatchObject({
        type: 'urn:ok:error:authorization-denied',
        title: 'Insufficient capability.',
      });
      expect(rig.principalIds).toEqual([]);
    } finally {
      await rig.close();
    }
  });

  test('published shared mode refuses a contributor mutation and audits the scope denial', async () => {
    const workspaceAudit = vi.fn();
    const rig = await bootNativeRig({
      authorization: contributorAuthorization(),
      workspaceAudit,
    });
    try {
      const response = await fetch(`${rig.baseUrl}/api/native-mutating`, {
        headers: { authorization: 'Bearer contributor-token' },
      });
      expect(response.status).toBe(403);
      expect(await response.json()).toMatchObject({
        type: 'urn:ok:error:authorization-denied',
        title: 'Published knowledge is read-only. Start or resume a proposal before editing.',
      });
      expect(rig.principalIds).toEqual([]);
      expect(workspaceAudit).toHaveBeenCalledWith(
        expect.objectContaining({
          event: 'security.workspace-authorization',
          reason: 'published-workspace-read-only',
        }),
      );
    } finally {
      await rig.close();
    }
  });

  test('proposal shared mode dispatches mutations only for the proposal owner', async () => {
    const rig = await bootNativeRig({
      authorization: contributorAuthorization(),
      runtimeScope: {
        kind: 'proposal',
        proposalId: 'proposal-1',
        principalId: 'human:contributor',
        branch: 'ok/proposals/owner/proposal-1',
      },
    });
    try {
      const response = await fetch(`${rig.baseUrl}/api/native-mutating`, {
        headers: { authorization: 'Bearer contributor-token' },
      });
      expect(response.status).toBe(200);
      expect(rig.principalIds).toEqual(['human:contributor']);
    } finally {
      await rig.close();
    }
  });

  test('a claimed route is served natively — the legacy dispatch never sees it', async () => {
    const rig = await bootNativeRig();
    try {
      const res = await fetch(`${rig.baseUrl}/api/native-ping`);
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ pong: true });
      expect(rig.legacyCalls).toEqual([]);
    } finally {
      await rig.close();
    }
  });

  test('an unclaimed route still flows through the legacy dispatch', async () => {
    const rig = await bootNativeRig();
    try {
      const res = await fetch(`${rig.baseUrl}/api/anything-else`);
      expect(res.status).toBe(299);
      expect(rig.legacyCalls).toEqual(['/api/anything-else']);
    } finally {
      await rig.close();
    }
  });

  test('a claimed path the table declines falls through to the legacy dispatch', async () => {
    const rig = await bootNativeRig();
    try {
      const res = await fetch(`${rig.baseUrl}/api/native-declined`);
      expect(res.status).toBe(299);
      expect(rig.legacyCalls).toEqual(['/api/native-declined']);
      // Decline is side-effect-FREE (pipeline docblock step 0): the declining
      // pipeline must not have touched the response — no request-id echo,
      // no CORS headers. The multi-group chain depends on this: every group
      // before the owning one declines the same request.
      expect(res.headers.get('x-request-id')).toBeNull();
      expect(res.headers.get('access-control-allow-methods')).toBeNull();
    } finally {
      await rig.close();
    }
  });

  test('a declined path skips the gates too — foreign Origin falls through, not 403', async () => {
    // The decline precedes the Origin gate: a chained group must never
    // refuse a request it does not own (the owning table — here the legacy
    // dispatch — applies its own gates).
    const rig = await bootNativeRig();
    try {
      const res = await fetch(`${rig.baseUrl}/api/native-declined`, {
        headers: { Origin: 'https://evil.example' },
      });
      expect(res.status).toBe(299);
      expect(rig.legacyCalls).toEqual(['/api/native-declined']);
    } finally {
      await rig.close();
    }
  });

  test('a dot-segment URL the router normalizes onto a claimed path still gets a response', async () => {
    const rig = await bootNativeRig();
    try {
      // Hono matches `/api/./native-ping` against the claimed path (the
      // adapter normalizes dot segments), but the pipeline resolves the RAW
      // req.url and declines it — the fall-through must hand the request to
      // the legacy dispatch rather than leaving it unanswered.
      const res = await rawRequest(rig.port, '/api/./native-ping', {});
      expect(res.status).toBe(299);
      expect(rig.legacyCalls).toEqual(['/api/./native-ping']);
    } finally {
      await rig.close();
    }
  });

  test('responses carry the x-request-id echo, honoring a well-formed inbound ID', async () => {
    const rig = await bootNativeRig();
    try {
      const minted = await fetch(`${rig.baseUrl}/api/native-ping`);
      expect(minted.headers.get('x-request-id')).toMatch(/^[A-Za-z0-9._-]{1,128}$/);

      const echoed = await fetch(`${rig.baseUrl}/api/native-ping`, {
        headers: { 'x-request-id': 'caller-chosen.id-42' },
      });
      expect(echoed.headers.get('x-request-id')).toBe('caller-chosen.id-42');
    } finally {
      await rig.close();
    }
  });

  test('a foreign Origin is refused before dispatch with the legacy problem shape', async () => {
    const rig = await bootNativeRig();
    try {
      const res = await fetch(`${rig.baseUrl}/api/native-ping`, {
        headers: { Origin: 'https://evil.example' },
      });
      expect(res.status).toBe(403);
      expect(res.headers.get('content-type')).toBe('application/problem+json');
      const body = (await res.json()) as { type?: string; title?: string };
      expect(body.type).toBe('urn:ok:error:invalid-origin');
      expect(body.title).toBe('Origin not allowed.');
      // The rejection still carries the request-id echo (identity slots
      // BEFORE the gates).
      expect(res.headers.get('x-request-id')).not.toBeNull();
    } finally {
      await rig.close();
    }
  });

  test('an allowed browser Origin gets verbatim CORS reflection with the exact header list', async () => {
    const rig = await bootNativeRig();
    try {
      const res = await fetch(`${rig.baseUrl}/api/native-ping`, {
        headers: { Origin: 'http://localhost:5173' },
      });
      expect(res.status).toBe(200);
      expect(res.headers.get('access-control-allow-origin')).toBe('http://localhost:5173');
      expect(res.headers.get('vary')).toContain('Origin');
      expect(res.headers.get('access-control-allow-methods')).toBe(
        'GET, POST, PUT, DELETE, OPTIONS',
      );
      expect(res.headers.get('access-control-allow-headers')).toBe(EXPECTED_ALLOW_HEADERS);
      expect(res.headers.get('access-control-expose-headers')).toBe('x-request-id');
    } finally {
      await rig.close();
    }
  });

  test('OPTIONS preflight answers 204 with the CORS headers', async () => {
    const rig = await bootNativeRig();
    try {
      const res = await fetch(`${rig.baseUrl}/api/native-ping`, {
        method: 'OPTIONS',
        headers: { Origin: 'http://localhost:5173' },
      });
      expect(res.status).toBe(204);
      expect(res.headers.get('access-control-allow-methods')).toBe(
        'GET, POST, PUT, DELETE, OPTIONS',
      );
    } finally {
      await rig.close();
    }
  });

  test('any forwarding header trips the proxied-request refusal on a native route', async () => {
    const rig = await bootNativeRig();
    try {
      const res = await rawRequest(rig.port, '/api/native-ping', {
        headers: { 'X-Forwarded-For': '203.0.113.7' },
      });
      expect(res.status).toBe(403);
      const body = parseProblem(res.body);
      expect(body.type).toBe('urn:ok:error:host-not-allowed');
      expect(body.detail ?? body.title).toContain('Proxied request refused');
    } finally {
      await rig.close();
    }
  });

  test('a mutating native route under a rebound Host is refused; a read route answers', async () => {
    const rig = await bootNativeRig();
    try {
      const refused = await rawRequest(rig.port, '/api/native-mutating', {
        headers: { Host: 'evil.example' },
      });
      expect(refused.status).toBe(403);
      expect(parseProblem(refused.body).type).toBe('urn:ok:error:host-not-allowed');

      // Read posture parity: Origin-gated but NOT Host-gated in normal mode.
      const read = await rawRequest(rig.port, '/api/native-ping', {
        headers: { Host: 'evil.example' },
      });
      expect(read.status).toBe(200);

      const allowed = await rawRequest(rig.port, '/api/native-mutating', {
        headers: { Host: 'localhost' },
      });
      expect(allowed.status).toBe(200);
    } finally {
      await rig.close();
    }
  });

  test('ephemeral mode Host-gates EVERY native /api route, including reads', async () => {
    const rig = await bootNativeRig({ ephemeral: true });
    try {
      const refused = await rawRequest(rig.port, '/api/native-ping', {
        headers: { Host: 'evil.example' },
      });
      expect(refused.status).toBe(403);
      expect(parseProblem(refused.body).type).toBe('urn:ok:error:host-not-allowed');

      const allowed = await rawRequest(rig.port, '/api/native-ping', {
        headers: { Host: 'localhost' },
      });
      expect(allowed.status).toBe(200);
    } finally {
      await rig.close();
    }
  });

  test('an owned URL with no handler gets the explicit RFC 9457 404', async () => {
    const rig = await bootNativeRig();
    try {
      const res = await fetch(`${rig.baseUrl}/api/native-empty`);
      expect(res.status).toBe(404);
      expect(res.headers.get('content-type')).toBe('application/problem+json');
      const body = (await res.json()) as { type?: string; title?: string };
      expect(body.type).toBe('urn:ok:error:not-found');
      expect(body.title).toBe('API endpoint not found.');
      expect(rig.legacyCalls).toEqual([]);
    } finally {
      await rig.close();
    }
  });

  test('a throwing handler surfaces as the typed 500 envelope, not a reset', async () => {
    const rig = await bootNativeRig();
    try {
      const res = await fetch(`${rig.baseUrl}/api/native-throw`);
      expect(res.status).toBe(500);
      expect(res.headers.get('content-type')).toBe('application/problem+json');
      const body = (await res.json()) as { type?: string };
      expect(body.type).toBe('urn:ok:error:internal-server-error');
    } finally {
      await rig.close();
    }
  });
});
