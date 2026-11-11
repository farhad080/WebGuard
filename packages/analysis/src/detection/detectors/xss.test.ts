import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import type { ParsedFile } from '../../ast/types.js';
import { parseSourceFiles } from '../../parse-project.js';
import { ProfilerService } from '../../profiler/profiler.js';
import { createDetectionContext } from '../context.js';
import { dedupeFindings } from '../dedupe.js';
import { DetectionEngine } from '../engine.js';
import type { FindingDraft } from '../types.js';
import { createDefaultDetectorRegistry } from './index.js';

const ROOT = fileURLToPath(new URL('../../../test/fixtures/xss', import.meta.url));
let findings: FindingDraft[];

beforeAll(async () => {
  const profile = await new ProfilerService().profile(ROOT);
  const files: ParsedFile[] = [];
  for await (const f of parseSourceFiles(ROOT, profile)) files.push(f);
  expect(files.filter((f) => f.parseError)).toEqual([]);
  const result = await new DetectionEngine(createDefaultDetectorRegistry()).run(
    createDetectionContext({ rootDir: ROOT, profile, files }),
  );
  expect(result.detectorErrors).toEqual([]);
  findings = dedupeFindings(result.findings);
});

const at = (path: string, line?: number) =>
  findings.filter((f) => f.filePath === path && (line === undefined || f.lineStart === line));

/** "dom" | "reflected" | "stored", read from the evidence label. */
const classOf = (f: FindingDraft) =>
  /^(DOM|Reflected|Stored) XSS:/.exec(f.evidence[0] ?? '')?.[1]?.toLowerCase();

describe('A4-xss: DOM', () => {
  it('flags el.innerHTML = this.searchValue (bound from a query param) as DOM XSS, high', () => {
    const [f] = at('frontend/search-box.component.ts');
    expect(f).toMatchObject({
      detectorId: 'A4-xss',
      owaspCategory: 'A05:2025-Injection',
      severity: 'high',
      confidence: 0.85,
      lineStart: 19,
      snippet: '    box.innerHTML = this.searchValue',
    });
    expect(classOf(f!)).toBe('dom');
    expect(f!.evidence[0]).toContain(
      'this.searchValue ← queryParam ← this.route.snapshot.queryParams.q',
    );
    expect(f!.explanation).toMatch(/^DOM-based XSS/);
    expect(f!.fixSuggestion).toMatch(/textContent/);
  });

  it('flags the Juice Shop search bypassSecurityTrustHtml and cites the [innerHTML] binding', () => {
    const [f] = at('frontend/search-result.component.ts', 29);
    expect(classOf(f!)).toBe('dom');
    expect(f!.confidence).toBe(0.85);
    expect(f!.evidence[0]).toContain(
      'rendered via [innerHTML]="searchValue" at frontend/search-result.component.html:3',
    );
  });

  it('flags React dangerouslySetInnerHTML fed by location.hash', () => {
    const [f] = at('frontend/Comment.jsx');
    expect(classOf(f!)).toBe('dom');
    expect(f!.evidence[0]).toContain('window.location.hash');
  });
});

describe('A4-xss: reflected', () => {
  it("flags res.send('<b>' + req.query.id + '</b>') as reflected XSS", () => {
    const [f] = at('server/routes/trackOrder.js', 4);
    expect(f).toMatchObject({ severity: 'high', confidence: 0.85 });
    expect(classOf(f!)).toBe('reflected');
    expect(f!.evidence[0]).toContain(
      '`req.query.id` is echoed into the HTML response by res.send()',
    );
    expect(f!.explanation).toMatch(/^Reflected XSS/);
  });

  it('follows res.status(...).send() chains and template literals', () => {
    const [f] = at('server/routes/trackOrder.js', 11);
    expect(classOf(f!)).toBe('reflected');
    expect(f!.evidence[0]).toContain('id ← req.params.id');
  });

  it('classifies URL data that round-trips through a service response as reflected (#28)', () => {
    const [f] = at('frontend/track-result.component.ts');
    expect(classOf(f!)).toBe('reflected');
    expect(f!.confidence).toBe(0.6); // passes through an unknown service call
    expect(f!.evidence[0]).toContain('round-trips through a service response');
  });
});

describe('A4-xss: stored', () => {
  it('flags a product model storing req.body.description that renders on a product page (#29)', () => {
    const [write] = at('server/routes/updateProduct.ts');
    expect(classOf(write!)).toBe('stored');
    expect(write!.confidence).toBe(0.8);
    expect(write!.evidence[0]).toContain('saved to the "description" field via product.update()');
    expect(write!.evidence[0]).toContain(
      'rendered as HTML at frontend/search-result.component.ts:19',
    );
    expect(write!.explanation).toMatch(/^Stored XSS/);

    const [render] = at('frontend/search-result.component.ts', 19);
    expect(classOf(render!)).toBe('stored');
    expect(render!.confidence).toBe(0.7); // render side, corroborated by the unsafe write
  });

  it('links the API-stored email to the admin list that renders it (#30)', () => {
    const [write] = at('server/routes/register.ts');
    expect(classOf(write!)).toBe('stored');
    expect(write!.evidence[0]).toContain('frontend/administration.component.ts:17');
    const [render] = at('frontend/administration.component.ts');
    expect(classOf(render!)).toBe('stored');
    expect(render!.confidence).toBe(0.8);
    expect(render!.evidence[0]).toContain('`user.email`');
  });
});

describe('A4-xss: no false positives', () => {
  it('ignores textContent, DOMPurify, Angular sanitize(), static HTML, and {{ }} / plain [innerHTML]', () => {
    expect(at('frontend/safe.component.ts')).toEqual([]);
    expect(at('frontend/safe.component.html')).toEqual([]);
  });

  it('ignores React {text} rendering and DOMPurify-sanitized dangerouslySetInnerHTML', () => {
    expect(at('frontend/SafeComment.jsx')).toEqual([]);
  });

  it('ignores JSON responses, escaped/numeric output, and sanitized storage', () => {
    expect(at('server/routes/safe.js')).toEqual([]);
  });

  it('produces exactly the expected findings (and classes) for the fixture project', () => {
    expect(findings.map((f) => `${classOf(f)} ${f.filePath}:${f.lineStart}`).sort()).toEqual([
      'dom frontend/Comment.jsx:4',
      'dom frontend/search-box.component.ts:19',
      'dom frontend/search-result.component.ts:29',
      'reflected frontend/track-result.component.ts:18',
      'reflected server/routes/trackOrder.js:11',
      'reflected server/routes/trackOrder.js:4',
      'stored frontend/administration.component.ts:17',
      'stored frontend/search-result.component.ts:19',
      'stored server/routes/register.ts:8',
      'stored server/routes/updateProduct.ts:9',
    ]);
    expect(new Set(findings.map((f) => f.severity))).toEqual(new Set(['high']));
  });
});
