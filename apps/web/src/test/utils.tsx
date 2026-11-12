import type { Finding, Scan, ScanRollup } from '@webguard/core';
import { render } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { vi } from 'vitest';
import { AppRoutes, Providers, createQueryClient } from '../App';
import { TOKEN_STORAGE_KEY } from '../auth/AuthContext';

// ---------------------------------------------------------------------------
// Mock API: a tiny router over `fetch`.
// ---------------------------------------------------------------------------

export interface MockRequest {
  method: string;
  path: string;
  query: URLSearchParams;
  body: unknown;
  headers: Headers;
}

export type MockResult = { status?: number; body?: unknown; headers?: Record<string, string> };
export type MockHandler = (
  req: MockRequest,
  params: Record<string, string>,
) => MockResult | Promise<MockResult>;

export function mockApi(routes: Record<string, MockHandler>) {
  const calls: MockRequest[] = [];
  const compiled = Object.entries(routes).map(([key, handler]) => {
    const [method, pattern] = key.split(' ') as [string, string];
    const names: string[] = [];
    const re = new RegExp(
      `^${pattern.replace(/[.]/g, '\\.').replace(/:(\w+)/g, (_m, n: string) => {
        names.push(n);
        return '([^/]+)';
      })}$`,
    );
    return { method, re, names, handler };
  });

  const fetchMock = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = new URL(String(input), 'http://localhost');
    const method = (init.method ?? 'GET').toUpperCase();
    const req: MockRequest = {
      method,
      path: url.pathname,
      query: url.searchParams,
      body: typeof init.body === 'string' ? JSON.parse(init.body) : init.body,
      headers: new Headers(init.headers),
    };
    calls.push(req);
    for (const r of compiled) {
      const m = r.method === method ? r.re.exec(url.pathname) : null;
      if (!m) continue;
      const params = Object.fromEntries(r.names.map((n, i) => [n, decodeURIComponent(m[i + 1]!)]));
      const res = await r.handler(req, params);
      const status = res.status ?? 200;
      if (status === 204) return new Response(null, { status });
      const isText = typeof res.body === 'string';
      return new Response(isText ? (res.body as string) : JSON.stringify(res.body ?? {}), {
        status,
        headers: {
          'Content-Type': isText ? 'text/plain' : 'application/json',
          ...res.headers,
        },
      });
    }
    return new Response(JSON.stringify({ error: `No mock for ${method} ${url.pathname}` }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' },
    });
  });
  vi.stubGlobal('fetch', fetchMock);
  return { calls, fetchMock };
}

// ---------------------------------------------------------------------------
// Fake XMLHttpRequest for the ZIP upload (progress events + JSON response).
// ---------------------------------------------------------------------------

export function installFakeXhr(respond: (url: string) => { status: number; body: unknown }) {
  const sent: { url: string; headers: Record<string, string>; body: unknown }[] = [];
  class FakeXhr {
    status = 0;
    response: unknown = null;
    responseType = '';
    upload: {
      onprogress:
        ((e: { lengthComputable: boolean; loaded: number; total: number }) => void) | null;
    } = {
      onprogress: null,
    };
    onload: (() => void) | null = null;
    onerror: (() => void) | null = null;
    onabort: (() => void) | null = null;
    private url = '';
    private headers: Record<string, string> = {};
    open(_method: string, url: string) {
      this.url = url;
    }
    setRequestHeader(k: string, v: string) {
      this.headers[k] = v;
    }
    abort() {
      this.onabort?.();
    }
    send(body: unknown) {
      sent.push({ url: this.url, headers: this.headers, body });
      setTimeout(
        () => this.upload.onprogress?.({ lengthComputable: true, loaded: 50, total: 100 }),
        5,
      );
      setTimeout(() => {
        this.upload.onprogress?.({ lengthComputable: true, loaded: 100, total: 100 });
        const r = respond(this.url);
        this.status = r.status;
        this.response = r.body;
        this.onload?.();
      }, 30);
    }
  }
  vi.stubGlobal('XMLHttpRequest', FakeXhr);
  return { sent };
}

// ---------------------------------------------------------------------------
// Rendering & fixtures
// ---------------------------------------------------------------------------

/** An unsigned JWT-shaped token whose payload expires in an hour (the SPA only reads `exp`). */
export function fakeToken(): string {
  const b64 = (o: object) => btoa(JSON.stringify(o)).replace(/=+$/, '');
  return `${b64({ alg: 'HS256' })}.${b64({ sub: 'u1', exp: Math.floor(Date.now() / 1000) + 3600 })}.sig`;
}

export function renderApp(path: string, { signedIn = true }: { signedIn?: boolean } = {}) {
  if (signedIn) window.localStorage.setItem(TOKEN_STORAGE_KEY, fakeToken());
  const client = createQueryClient();
  client.setDefaultOptions({ queries: { ...client.getDefaultOptions().queries, retry: false } });
  return {
    client,
    ...render(
      <Providers client={client}>
        <MemoryRouter initialEntries={[path]}>
          <AppRoutes />
        </MemoryRouter>
      </Providers>,
    ),
  };
}

export const user = { id: 'u1', email: 'alice@example.com' };

export function rollup(overrides: Partial<ScanRollup> = {}): ScanRollup {
  return {
    total: 4,
    bySeverity: { critical: 1, high: 2, medium: 1, low: 0, info: 0 },
    byOwaspCategory: { 'A05:2025-Injection': 3, 'A01:2025-Broken Access Control': 1 },
    riskScore: 62,
    grade: 'D',
    weightedRisk: 21.4,
    gradeReason: 'capped at D: 1 high-confidence critical finding',
    computedAt: '2026-11-12T10:00:00.000Z',
    ...overrides,
  };
}

export function scan(overrides: Partial<Scan> = {}): Scan {
  return {
    id: 's1',
    projectId: 'p1',
    status: 'queued',
    startedAt: null,
    finishedAt: null,
    summary: null,
    createdAt: '2026-11-12T10:00:00.000Z',
    ...overrides,
  };
}

let seq = 0;
export function finding(overrides: Partial<Finding> = {}): Finding {
  seq += 1;
  return {
    id: `f${seq}`,
    scanId: 's1',
    detectorId: 'A1-sql-injection',
    owaspCategory: 'A05:2025-Injection',
    severity: 'high',
    confidence: 0.9,
    filePath: 'src/db.js',
    lineStart: 10,
    lineEnd: 10,
    snippet: 'db.query("SELECT * FROM users WHERE id = " + req.params.id)',
    explanation: 'User input is concatenated into a SQL query.',
    fixSuggestion: 'Use parameterized queries.',
    contributingDetectors: ['A1-sql-injection'],
    evidence: ['req.params.id flows into db.query'],
    cwe: 'CWE-89',
    remediation: null,
    createdAt: '2026-11-12T10:00:00.000Z',
    ...overrides,
  };
}
