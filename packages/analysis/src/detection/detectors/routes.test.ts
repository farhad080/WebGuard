import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import type { ParsedFile } from '../../ast/types.js';
import { parseSourceFiles } from '../../parse-project.js';
import { ProfilerService } from '../../profiler/profiler.js';
import { getRouteTable, type RouteTable } from '../../routes/route-table.js';
import { createDetectionContext } from '../context.js';
import { dedupeFindings } from '../dedupe.js';
import { DetectionEngine } from '../engine.js';
import type { FindingDraft } from '../types.js';
import { createDefaultDetectorRegistry } from './index.js';

const fixture = (name: string) =>
  fileURLToPath(new URL(`../../../test/fixtures/${name}`, import.meta.url));

async function scan(root: string): Promise<{ findings: FindingDraft[]; table: RouteTable }> {
  const profile = await new ProfilerService().profile(root);
  const files: ParsedFile[] = [];
  for await (const f of parseSourceFiles(root, profile)) files.push(f);
  expect(files.filter((f) => f.parseError)).toEqual([]);
  const ctx = createDetectionContext({ rootDir: root, profile, files });
  const result = await new DetectionEngine(createDefaultDetectorRegistry()).run(ctx);
  expect(result.detectorErrors).toEqual([]);
  return { findings: dedupeFindings(result.findings), table: getRouteTable(ctx) };
}

let findings: FindingDraft[];
let table: RouteTable;

beforeAll(async () => {
  ({ findings, table } = await scan(fixture('routes')));
});

const of = (id: string) => findings.filter((f) => f.detectorId === id);
const at = (id: string, path: string, line?: number) =>
  of(id).filter((f) => f.filePath === path && (line === undefined || f.lineStart === line));
const route = (method: string, path: string) =>
  table.routes.find((r) => r.method === method && r.path === path)!;

describe('RouteTable', () => {
  it('extracts Express routes with resolved handlers and middleware chains', () => {
    const r = route('GET', '/rest/basket/:id');
    expect(r).toMatchObject({
      framework: 'express',
      authMechanism: 'bearer',
      authenticated: true,
      hasAuthorization: false,
    });
    expect(r.handlerFile?.path).toBe('routes/basket.ts');
    expect(r.middlewareChain.filter((m) => !m.infrastructure).map((m) => m.name)).toEqual([
      'security.isAuthorized()',
    ]);
    // app.use(session(...)) is inherited but recognized as infrastructure, not auth.
    expect(r.middlewareChain.some((m) => m.inherited && m.infrastructure)).toBe(true);
  });

  it('infers auth mechanisms: bearer, cookie-session (middleware or inline cookie), none', () => {
    expect(route('POST', '/api/Products/:id/reviews').authMechanism).toBe('bearer');
    expect(route('POST', '/settings')).toMatchObject({
      authMechanism: 'cookie-session',
      csrfProtected: true,
    });
    expect(route('POST', '/profile')).toMatchObject({
      authMechanism: 'cookie-session',
      authenticated: true,
    });
    expect(route('DELETE', '/api/Feedbacks/:id')).toMatchObject({
      authMechanism: 'none',
      authenticated: false,
    });
    expect(route('DELETE', '/api/Users/:id').hasAuthorization).toBe(true);
    expect(table.usesSessions).toBe(true);
    expect(table.sessionSameSite).toBeUndefined();
  });

  it('extracts NestJS controllers with class- and method-level guards', () => {
    expect(route('DELETE', '/admin/users/:id')).toMatchObject({
      framework: 'nest',
      authenticated: false,
    });
    expect(route('GET', '/orders/:id')).toMatchObject({
      authMechanism: 'bearer',
      hasAuthorization: false,
    });
    expect(route('DELETE', '/reports/:id').hasAuthorization).toBe(true);
  });
});

describe('A8-broken-access-control', () => {
  it("flags app.delete('/api/Feedbacks/:id', handler) with no authz (#22) as a medium-confidence candidate", () => {
    const [f] = at('A8-broken-access-control', 'server.ts', 18);
    expect(f).toMatchObject({
      owaspCategory: 'A01:2025-Broken Access Control',
      severity: 'high',
      confidence: 0.6,
    });
    expect(f!.evidence[0]).toMatch(
      /^Candidate \(missing authorization\): DELETE \/api\/Feedbacks\/:id/,
    );
    expect(f!.explanation).toMatch(/^Candidate \(confirm manually\)/);
  });

  it('flags the admin config route and notes it is guarded only client-side (#20)', () => {
    const [f] = at('A8-broken-access-control', 'server.ts', 31);
    expect(f!.evidence[0]).toContain(
      'guarded only client-side (canActivate at frontend/app.routing.ts:7)',
    );
  });

  it('flags Basket.findOne({ where: { id } }) and findByPk(req.params.id) without owner checks (#21)', () => {
    expect(
      at('A8-broken-access-control', 'routes/basket.ts').map((f) => [f.lineStart, f.confidence]),
    ).toEqual([
      [8, 0.55],
      [15, 0.55],
      [30, 0.55],
    ]);
    expect(at('A8-broken-access-control', 'routes/basket.ts', 15)[0]!.evidence[0]).toContain(
      'BasketModel.findByPk(req.params.id)',
    );
  });

  it('flags a client-supplied BasketId when adding items (#24)', () => {
    expect(at('A8-broken-access-control', 'routes/basket.ts', 30)[0]!.evidence[0]).toContain(
      '"BasketId"',
    );
  });

  it('does not flag owner-scoped lookups, admin-guarded routes, or token-derived ids', () => {
    expect(at('A8-broken-access-control', 'routes/basket.ts', 22)).toEqual([]); // UserId: req.user.id
    expect(at('A8-broken-access-control', 'routes/users.ts')).toEqual([]); // admin delete, req.auth.id
    expect(at('A8-broken-access-control', 'routes/profile.ts')).toEqual([]); // id from the auth cookie
    expect(at('A8-broken-access-control', 'routes/settings.ts')).toEqual([]);
  });

  it('handles NestJS: unguarded admin delete, IDOR via @Param, RolesGuard suppression', () => {
    expect(
      at('A8-broken-access-control', 'nest/admin.controller.ts').map((f) => f.lineStart),
    ).toEqual([10, 23]);
  });
});

describe('A9-mass-assignment', () => {
  it('flags User.create(req.body) on a model with a role field at high confidence', () => {
    const [f] = at('A9-mass-assignment', 'routes/users.ts', 8);
    expect(f).toMatchObject({ severity: 'high', confidence: 0.85 });
    expect(f!.evidence[0]).toContain('privileged field(s) role');
  });

  it('flags feedback created from the whole body, letting the client set UserId (#23)', () => {
    expect(at('A9-mass-assignment', 'routes/feedback.ts')[0]!.evidence[0]).toContain('UserId');
  });

  it("does not flag pick(req.body, ['email','password']) or a schema-validated body", () => {
    expect(at('A9-mass-assignment', 'routes/users.ts', 16)).toEqual([]);
    expect(at('A9-mass-assignment', 'routes/users.ts', 24)).toEqual([]);
  });

  it("flags attributes: req.query.fields.split(',') as over-selection (#13)", () => {
    const [f] = at('A9-mass-assignment', 'routes/users.ts', 32);
    expect(f).toMatchObject({ severity: 'high', confidence: 0.8 });
    expect(f!.evidence[0]).toContain('password');
    expect(f!.fixSuggestion).toMatch(/fixed server-side attribute list/);
  });
});

describe('A10-missing-csrf', () => {
  it('flags the cookie-authenticated POST /profile with no CSRF protection (#25)', () => {
    const [f] = of('A10-missing-csrf');
    expect(f).toMatchObject({
      filePath: 'server.ts',
      lineStart: 44,
      severity: 'medium',
      confidence: 0.6,
    });
    expect(f!.evidence[0]).toContain('req.cookies.token');
    expect(of('A10-missing-csrf')).toHaveLength(1);
  });

  it('does not flag bearer-token APIs or CSRF-token protected session routes', () => {
    const lines = of('A10-missing-csrf').map((f) => f.lineStart);
    expect(lines).not.toContain(46); // bearer API
    expect(lines).not.toContain(48); // csrfProtection
  });

  it('does not flag a session app whose cookie is SameSite=Strict', async () => {
    const { findings: samesite, table: t } = await scan(fixture('routes-samesite'));
    expect(t.sessionSameSite).toBe('strict');
    expect(samesite.filter((f) => f.detectorId === 'A10-missing-csrf')).toEqual([]);
  });
});

describe('overall', () => {
  it('produces exactly the expected route-level findings', () => {
    expect(
      findings
        .filter((f) => /^A(8|9|10)-/.test(f.detectorId))
        .map((f) => `${f.detectorId} ${f.filePath}:${f.lineStart}`)
        .sort(),
    ).toEqual([
      'A10-missing-csrf server.ts:44',
      'A8-broken-access-control nest/admin.controller.ts:10',
      'A8-broken-access-control nest/admin.controller.ts:23',
      'A8-broken-access-control routes/basket.ts:15',
      'A8-broken-access-control routes/basket.ts:30',
      'A8-broken-access-control routes/basket.ts:8',
      'A8-broken-access-control server.ts:18',
      'A8-broken-access-control server.ts:31',
      'A9-mass-assignment routes/feedback.ts:14',
      'A9-mass-assignment routes/users.ts:32',
      'A9-mass-assignment routes/users.ts:8',
    ]);
    // Every A8 finding is honestly labelled a candidate at medium confidence.
    expect(
      of('A8-broken-access-control').every(
        (f) => f.confidence <= 0.6 && f.evidence[0]!.startsWith('Candidate'),
      ),
    ).toBe(true);
  });
});
