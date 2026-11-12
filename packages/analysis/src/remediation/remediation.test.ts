import { rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { materializeSecretsProject } from '../../test/secrets-project.js';
import type { ParsedFile } from '../ast/types.js';
import { createDetectionContext } from '../detection/context.js';
import { dedupeFindings } from '../detection/dedupe.js';
import { createDefaultDetectorRegistry } from '../detection/detectors/index.js';
import { DetectionEngine } from '../detection/engine.js';
import type { DetectionContext, FindingDraft } from '../detection/types.js';
import { parseSourceFiles } from '../parse-project.js';
import { ProfilerService } from '../profiler/profiler.js';
import { RemediationService, TEMPLATE_DETECTOR_IDS } from './service.js';
import type { RemediationLlmProvider } from './types.js';

const fixture = (name: string) =>
  fileURLToPath(new URL(`../../test/fixtures/${name}`, import.meta.url));
const silent = { warn: () => undefined };

async function scan(root: string): Promise<{ findings: FindingDraft[]; ctx: DetectionContext }> {
  const profile = await new ProfilerService().profile(root);
  const files: ParsedFile[] = [];
  for await (const f of parseSourceFiles(root, profile)) files.push(f);
  const ctx = createDetectionContext({ rootDir: root, profile, files });
  const result = await new DetectionEngine(createDefaultDetectorRegistry(), { logger: silent }).run(
    ctx,
  );
  return { findings: dedupeFindings(result.findings), ctx };
}

describe('template coverage', () => {
  it('has a template set for every built-in detector', () => {
    const builtins = createDefaultDetectorRegistry()
      .list()
      .map((d) => d.id);
    expect(builtins.filter((id) => !TEMPLATE_DETECTOR_IDS.includes(id))).toEqual([]);
    expect(builtins).toHaveLength(13); // A1-A12 + the example detector
  });

  it('gives every finding from every fixture a complete remediation', async () => {
    const service = new RemediationService({ logger: silent });
    const secrets = await materializeSecretsProject();
    try {
      const roots = [
        ...['mini-express', 'injection', 'xss', 'crypto', 'routes', 'exposure', 'deps'].map(
          fixture,
        ),
        secrets,
      ];
      const seenDetectors = new Set<string>();
      for (const root of roots) {
        const { findings, ctx } = await scan(root);
        for (const f of await service.enrichFindings(findings, ctx)) {
          seenDetectors.add(f.detectorId);
          const r = f.remediation;
          expect(r.templateId.startsWith(f.detectorId), `${f.detectorId} → ${r.templateId}`).toBe(
            true,
          );
          expect(r.why.length, f.detectorId).toBeGreaterThan(20);
          expect(r.impact.length, f.detectorId).toBeGreaterThan(10);
          expect(r.steps.length, f.detectorId).toBeGreaterThanOrEqual(2);
          expect(r.secureExample.after.trim(), f.detectorId).not.toBe('');
          expect(r.secureExample.before.trim(), f.detectorId).not.toBe('');
          expect(r.references.length, f.detectorId).toBeGreaterThan(0);
          expect(r.references.every((ref) => ref.url.startsWith('https://'))).toBe(true);
          expect(r.generatedBy).not.toBe('llm');
        }
      }
      // A1-A12 all produced findings somewhere in the fixtures.
      expect([...seenDetectors].filter((d) => /^A\d+-/.test(d)).sort()).toHaveLength(12);
    } finally {
      await rm(secrets, { recursive: true, force: true });
    }
  });

  it('falls back to a generic remediation for unknown detectors', () => {
    const r = new RemediationService().remediate({
      detectorId: 'custom-rule',
      owaspCategory: 'A05:2025-Injection',
      severity: 'high',
      confidence: 0.5,
      filePath: 'a.js',
      lineStart: 1,
      lineEnd: 1,
      snippet: 'danger()',
      explanation: 'Custom explanation of the risk.',
      fixSuggestion: 'Do the safe thing.',
      contributingDetectors: ['custom-rule'],
      evidence: ['x'],
      cwe: null,
    });
    expect(r).toMatchObject({
      templateId: 'custom-rule/generic',
      why: 'Custom explanation of the risk.',
      generatedBy: 'template',
    });
    expect(r.steps).toContain('Do the safe thing.');
  });
});

describe('contextualized secure examples', () => {
  it('rewrites the Juice Shop login query into a parameterized call using its real fields', async () => {
    const { findings, ctx } = await scan(fixture('injection'));
    const enriched = await new RemediationService().enrichFindings(findings, ctx);
    const login = enriched.find(
      (f) => f.detectorId === 'A1-sql-injection' && f.filePath === 'routes/sqli/login.ts',
    )!;
    expect(login.remediation).toMatchObject({
      templateId: 'A1-sql-injection',
      generatedBy: 'template+context',
    });
    const ex = login.remediation.secureExample;
    expect(ex).toMatchObject({ language: 'typescript', contextualized: true });
    expect(ex.before).toContain("WHERE email = '${req.body.email || ''}'");
    expect(ex.after).toBe(
      [
        'models.sequelize.query(',
        "  'SELECT * FROM Users WHERE email = $1 AND password = $2 AND deletedAt IS NULL',",
        "  { bind: [req.body.email || '', security.hash(req.body.password || '')], model: UserModel, plain: true }",
        ')',
      ].join('\n'),
    );
    expect(ex.after).not.toContain('${');
  });

  it('keeps LIKE wildcards in the bound value and handles queries built in a variable', async () => {
    const { findings, ctx } = await scan(fixture('injection'));
    const enriched = await new RemediationService().enrichFindings(findings, ctx);
    const a1 = (path: string) =>
      enriched.find((f) => f.detectorId === 'A1-sql-injection' && f.filePath === path)!;
    expect(a1('routes/sqli/search.ts').remediation.secureExample.after).toContain(
      'name LIKE $1 OR description LIKE $2',
    );
    expect(a1('routes/sqli/search.ts').remediation.secureExample.after).toContain(
      'bind: [`%${criteria}%`, `%${criteria}%`]',
    );
    expect(a1('routes/sqli/raw-concat.js').remediation.secureExample.after).toBe(
      "const sql = 'SELECT * FROM orders WHERE status = ?';\ndb.all(sql, [status], (err, rows) => res.json(rows))",
    );
  });

  it("contextualizes other detectors with the finding's own names", async () => {
    const service = new RemediationService();
    const pick = async (fx: string, id: string, path: string, line?: number) => {
      const { findings, ctx } = await scan(fixture(fx));
      return (await service.enrichFindings(findings, ctx)).find(
        (f) =>
          f.detectorId === id &&
          f.filePath === path &&
          (line === undefined || f.lineStart === line),
      )!.remediation.secureExample;
    };
    expect((await pick('xss', 'A4-xss', 'frontend/search-box.component.ts')).after).toBe(
      'box.textContent = this.searchValue',
    );
    expect((await pick('xss', 'A4-xss', 'server/routes/trackOrder.js', 4)).after).toBe(
      "res.send('<b>' + escapeHtml(req.query.id) + '</b>');",
    );
    expect((await pick('crypto', 'A6-weak-crypto', 'server/lib/insecurity.ts', 5)).after).toBe(
      'export const hash = async (data: string) => await argon2.hash(data)',
    );
    expect((await pick('crypto', 'A6-weak-crypto', 'legacy/auth.py')).after).toBe(
      'user.password_hash = PasswordHasher().hash(password)',
    );
    expect((await pick('routes', 'A8-broken-access-control', 'routes/basket.ts', 15)).after).toBe(
      'const basket = await BasketModel.findOne({ where: { id: req.params.id, UserId: req.user.id } })',
    );
    expect((await pick('deps', 'A11-vulnerable-deps', 'package.json', 12)).after).toBe(
      '"sanitize-html": "^1.4.3"',
    );
  });

  it('never puts the secret back into a secrets example', async () => {
    const root = await materializeSecretsProject();
    try {
      const { findings, ctx } = await scan(root);
      const enriched = await new RemediationService().enrichFindings(findings, ctx);
      const aws = enriched.find((f) => f.filePath === 'server/config/aws.ts' && f.lineStart === 3)!;
      expect(aws.remediation.secureExample.after).toBe(
        'secretAccessKey: process.env.SECRET_ACCESS_KEY,',
      );
      expect(JSON.stringify(enriched.map((f) => f.remediation))).not.toMatch(
        /AKIA2E0A8F3B244C9986|IamUsedForTesting/,
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe('optional LLM assist', () => {
  function fakeProvider() {
    const calls: string[] = [];
    const provider: RemediationLlmProvider = {
      id: 'fake-llm',
      draftSecureSnippet: async (input) => {
        calls.push(input.detectorId);
        return '// drafted by the fake provider';
      },
    };
    return { provider, calls };
  }

  it('is fully bypassed when the flag is off, even with a provider configured', async () => {
    const { findings, ctx } = await scan(fixture('crypto'));
    const { provider, calls } = fakeProvider();
    const enriched = await new RemediationService({
      llm: { enabled: false, provider },
    }).enrichFindings(findings, ctx);
    expect(calls).toEqual([]);
    expect(enriched.every((f) => f.remediation.generatedBy !== 'llm')).toBe(true);
    expect(
      enriched.every((f) => f.remediation.steps.length > 0 && f.remediation.secureExample.after),
    ).toBe(true);
  });

  it('drafts only findings without a deterministic rewrite when enabled', async () => {
    const { findings, ctx } = await scan(fixture('crypto'));
    const { provider, calls } = fakeProvider();
    const enriched = await new RemediationService({
      llm: { enabled: true, provider },
    }).enrichFindings(findings, ctx);
    const drafted = enriched.filter((f) => f.remediation.generatedBy === 'llm');
    expect(drafted.length).toBe(calls.length);
    expect(drafted.length).toBeGreaterThan(0);
    // Deterministic rewrites (e.g. MD5 password hashing) are never sent to the LLM.
    expect(
      enriched.find((f) => f.filePath === 'server/routes/changePassword.js')!.remediation
        .generatedBy,
    ).toBe('template+context');
    expect(drafted[0]!.remediation.secureExample.note).toMatch(/fake-llm; review/);
  });

  it('keeps the template when the provider fails', async () => {
    const { findings, ctx } = await scan(fixture('crypto'));
    const provider: RemediationLlmProvider = {
      id: 'broken',
      draftSecureSnippet: async () => {
        throw new Error('offline');
      },
    };
    const enriched = await new RemediationService({
      llm: { enabled: true, provider },
      logger: silent,
    }).enrichFindings(findings, ctx);
    expect(enriched.every((f) => f.remediation.generatedBy !== 'llm')).toBe(true);
  });
});
