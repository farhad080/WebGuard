import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { ScanReport, ScanSummary } from '@webguard/core';
import type { Worker } from 'bullmq';
import request from 'supertest';
import { afterAll, afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createUserWithToken, resetDatabase } from '../../test/helpers.js';
import { buildZip } from '../../test/zip-writer.js';
import { createApp } from '../app.js';
import { prisma } from '../db.js';
import { processScan } from '../scans/process-scan.js';
import { closeScanQueue, createScanWorker, getScanQueue } from '../scans/queue.js';
import { getStorage } from '../scans/storage.js';
import { escapeHtml, highlight } from './highlight.js';
import { findChromium } from './render-pdf.js';
import { computeRollup, RISK_MODEL } from './rollup.js';

const app = createApp();
let alice: string;
let bob: string;
let projectId: string;
let worker: Worker | undefined;

beforeEach(async () => {
  await resetDatabase();
  await getScanQueue().obliterate({ force: true });
  await getStorage().deletePrefix('scans');
  alice = (await createUserWithToken('alice@example.com')).auth;
  bob = (await createUserWithToken('bob@example.com')).auth;
  const res = await request(app)
    .post('/api/projects')
    .set('Authorization', alice)
    .send({ name: 'Juice Shop' });
  projectId = res.body.id;
});

afterEach(async () => {
  await worker?.close();
  worker = undefined;
});

afterAll(async () => {
  await getScanQueue().obliterate({ force: true });
  await closeScanQueue();
  await prisma.$disconnect();
});

/** Uploads an analysis fixture project and runs the scan pipeline on it. */
async function scanFixture(name: string): Promise<string> {
  const root = fileURLToPath(
    new URL(`../../../../packages/analysis/test/fixtures/${name}`, import.meta.url),
  );
  const files = (await readdir(root, { recursive: true, withFileTypes: true }))
    .filter((e) => e.isFile())
    .map((e) => path.join(e.parentPath, e.name));
  const zip = buildZip(
    await Promise.all(
      files.map(async (abs) => ({
        name: path.relative(root, abs).split(path.sep).join('/'),
        data: await readFile(abs),
      })),
    ),
  );
  const res = await request(app)
    .post(`/api/projects/${projectId}/scans`)
    .set('Authorization', alice)
    .attach('file', zip, { filename: `${name}.zip`, contentType: 'application/zip' });
  expect(res.status).toBe(201);
  await processScan(res.body.id);
  return res.body.id;
}

describe('computeRollup (risk model)', () => {
  it('scores an empty scan as A', () => {
    expect(computeRollup([])).toMatchObject({
      total: 0,
      riskScore: 0,
      grade: 'A',
      weightedRisk: 0,
    });
  });

  it('weights severity × confidence and saturates toward 100', () => {
    const r = computeRollup([
      { severity: 'high', owaspCategory: 'A05:2025-Injection', confidence: 0.5 }, // 2.5
      { severity: 'medium', owaspCategory: 'A02:2025-Security Misconfiguration', confidence: 1 }, // 2
      { severity: 'info', owaspCategory: 'A06:2025-Insecure Design', confidence: 1 }, // 0
    ]);
    expect(r.weightedRisk).toBe(4.5);
    expect(r.riskScore).toBe(Math.round(100 * (1 - Math.exp(-4.5 / RISK_MODEL.saturation))));
    expect(r.grade).toBe('B'); // 16
    expect(r.bySeverity).toEqual({ critical: 0, high: 1, medium: 1, low: 0, info: 1 });
  });

  it('caps the grade at D when a high-confidence critical finding exists', () => {
    const r = computeRollup([
      { severity: 'critical', owaspCategory: 'A05:2025-Injection', confidence: 0.9 },
    ]);
    expect(r.riskScore).toBe(30); // would be C on score alone
    expect(r.grade).toBe('D');
    expect(r.gradeReason).toMatch(/capped at D/);
    // A low-confidence critical does not trigger the cap.
    expect(
      computeRollup([
        { severity: 'critical', owaspCategory: 'A05:2025-Injection', confidence: 0.4 },
      ]).grade,
    ).toBe('B');
  });
});

describe('scan rollup persisted by the worker', () => {
  it('matches the persisted findings for a fixture scan', async () => {
    const scanId = await scanFixture('injection');
    const scan = await prisma.scan.findUniqueOrThrow({ where: { id: scanId } });
    const { rollup, findingsTotal, findingsBySeverity } = scan.summaryJson as ScanSummary;
    const rows = await prisma.finding.findMany({ where: { scanId } });

    expect(rollup).toBeDefined();
    expect(rollup!.total).toBe(rows.length);
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const byCategory: Record<string, number> = {};
    let weighted = 0;
    for (const r of rows) {
      bySeverity[r.severity]++;
      byCategory[r.owaspCategory] = (byCategory[r.owaspCategory] ?? 0) + 1;
      weighted += RISK_MODEL.severityWeights[r.severity] * r.confidence;
    }
    expect(rollup!.bySeverity).toEqual(bySeverity);
    expect(rollup!.byOwaspCategory).toEqual(byCategory);
    expect(rollup!.weightedRisk).toBeCloseTo(weighted, 1);
    expect(rollup!.riskScore).toBe(
      Math.round(100 * (1 - Math.exp(-rollup!.weightedRisk / RISK_MODEL.saturation))),
    );
    expect(rollup!.grade).toBe('F'); // 7 critical SQLi/NoSQLi/SSTI findings
    // The legacy summary counters mirror the rollup.
    expect(findingsTotal).toBe(rollup!.total);
    expect(findingsBySeverity).toEqual(rollup!.bySeverity);
  });
});

describe('GET /api/scans/:id/report.json', () => {
  it('returns the full structured report with remediation and informational notes', async () => {
    const scanId = await scanFixture('injection');
    const res = await request(app)
      .get(`/api/scans/${scanId}/report.json`)
      .set('Authorization', alice);
    expect(res.status).toBe(200);
    const report = res.body as ScanReport;
    expect(report).toMatchObject({
      reportVersion: 1,
      project: { id: projectId, name: 'Juice Shop' },
      scan: { id: scanId, status: 'completed' },
    });
    expect(report.profile!.languages.map((l) => l.language)).toContain('typescript');
    expect(report.rollup.total).toBe(report.findings.length);
    expect(report.findings.length).toBeGreaterThan(0);
    // Most severe first.
    expect(report.findings[0]!.severity).toBe('critical');
    for (const f of report.findings) {
      expect(f.remediation, f.detectorId).not.toBeNull();
      expect(f.remediation!.steps.length).toBeGreaterThan(0);
      expect(f.remediation!.secureExample.after).toBeTruthy();
    }
    expect(report.informationalNotes.flatMap((n) => n.references)).toEqual([
      'Juice Shop #15',
      'Juice Shop #17',
      'Juice Shop #33',
      'Juice Shop #34',
    ]);
  });
});

describe('GET /api/scans/:id/report.html', () => {
  it('renders every finding as self-contained HTML with no external resources', async () => {
    const scanId = await scanFixture('xss');
    const json = (
      await request(app).get(`/api/scans/${scanId}/report.json`).set('Authorization', alice)
    ).body as ScanReport;
    const res = await request(app)
      .get(`/api/scans/${scanId}/report.html`)
      .set('Authorization', alice);
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/text\/html/);
    const html = res.text;

    expect(html.match(/<article class="finding"/g)?.length).toBe(json.findings.length);
    // No external assets of any kind: scripts, stylesheets, images, fonts, imports.
    expect(html).not.toMatch(/<script/i);
    expect(html).not.toMatch(/<link\b/i);
    expect(html).not.toMatch(/\bsrc\s*=\s*["']?https?:/i);
    expect(html).not.toMatch(/url\(\s*["']?https?:/i);
    expect(html).not.toMatch(/@import/i);
    // The only http(s) URLs are reference links (anchors), never loaded resources.
    const urls = [...html.matchAll(/https?:\/\/[^\s"'<>)]+/g)].map((m) => m[0]);
    expect(urls.every((u) => html.includes(`<a href="${u}"`))).toBe(true);
    expect(html).toContain("default-src 'none'");

    // Untrusted snippets are escaped (the XSS fixture contains '<b>' + req.query.id).
    expect(html).not.toContain("'<b>' + req.query.id");
    expect(html).toContain('&lt;b&gt;');
    // Grade, severity cards, remediation, and the informational section are present.
    expect(html).toContain(`>${json.rollup.grade}</b>`);
    expect(html).toContain('How to fix');
    expect(html).toContain('Review manually (informational)');
  });
});

describe('GET /api/scans/:id/report.pdf', () => {
  it.skipIf(!findChromium())(
    'renders a PDF in the worker, stores it, and records a report artifact',
    async () => {
      const scanId = await scanFixture('injection');
      worker = createScanWorker(); // the PDF is rendered by the worker, not the request
      const res = await request(app)
        .get(`/api/scans/${scanId}/report.pdf`)
        .set('Authorization', alice)
        .buffer(true)
        .parse((r, cb) => {
          const chunks: Buffer[] = [];
          r.on('data', (c: Buffer) => chunks.push(c));
          r.on('end', () => cb(null, Buffer.concat(chunks)));
        });
      expect(res.status).toBe(200);
      expect(res.headers['content-type']).toBe('application/pdf');
      expect(res.headers['content-disposition']).toContain(`webguard-report-${scanId}.pdf`);
      const pdf = res.body as Buffer;
      expect(pdf.length).toBeGreaterThan(1000);
      expect(pdf.subarray(0, 4).toString('latin1')).toBe('%PDF');

      const artifacts = await prisma.artifact.findMany({ where: { scanId, kind: 'report' } });
      expect(artifacts).toEqual([
        expect.objectContaining({ storageKey: `scans/${scanId}/report.pdf` }),
      ]);

      // Second request streams the stored file (no new job).
      await worker.close();
      worker = undefined;
      const again = await request(app)
        .get(`/api/scans/${scanId}/report.pdf`)
        .set('Authorization', alice);
      expect(again.status).toBe(200);
      expect(await prisma.artifact.count({ where: { scanId, kind: 'report' } })).toBe(1);
    },
  );
});

describe('report ownership and state', () => {
  it("returns 404 for another user's scan on every report endpoint", async () => {
    const scanId = await scanFixture('injection');
    for (const ext of ['json', 'html', 'pdf']) {
      expect(
        (await request(app).get(`/api/scans/${scanId}/report.${ext}`).set('Authorization', bob))
          .status,
      ).toBe(404);
      expect((await request(app).get(`/api/scans/${scanId}/report.${ext}`)).status).toBe(401);
    }
    expect(
      (await request(app).get('/api/scans/not-a-uuid/report.json').set('Authorization', alice))
        .status,
    ).toBe(404);
  });

  it('returns 409 for a scan that has not completed', async () => {
    const zip = buildZip([{ name: 'a.js', data: 'x' }]);
    const res = await request(app)
      .post(`/api/projects/${projectId}/scans`)
      .set('Authorization', alice)
      .attach('file', zip, { filename: 'a.zip', contentType: 'application/zip' });
    expect(
      (await request(app).get(`/api/scans/${res.body.id}/report.json`).set('Authorization', alice))
        .status,
    ).toBe(409);
  });
});

describe('highlighter', () => {
  it('escapes everything and only adds its own spans', () => {
    const out = highlight(`const x = "<img src=x onerror=alert(1)>"; // <script>`, 'typescript');
    expect(out).not.toMatch(/<img|<script/);
    expect(out).toContain('<span class="tk">const</span>');
    expect(out).toContain('<span class="ts">&quot;&lt;img src=x onerror=alert(1)&gt;&quot;</span>');
    expect(escapeHtml(`"'<>&`)).toBe('&quot;&#39;&lt;&gt;&amp;');
  });
});
