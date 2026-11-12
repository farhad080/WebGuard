import type { Finding, ScanReport, Severity } from '@webguard/core';
import { escapeHtml as e, highlight } from './highlight.js';
import { RISK_MODEL } from './rollup.js';

/**
 * Self-contained HTML report: inline CSS, no scripts, no external assets (a CSP meta tag
 * blocks any network load even if the file is opened offline). Print-friendly, so the same
 * markup is rendered to PDF by headless Chromium.
 */

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const CSS = `
:root { --fg:#1d2433; --muted:#5b6475; --line:#e3e6ec; --bg:#ffffff; --panel:#f6f7f9;
  --critical:#b42318; --high:#d9480f; --medium:#b7791f; --low:#2f6fb0; --info:#5b6475;
  --code-bg:#0f172a; --code-fg:#e2e8f0; }
* { box-sizing: border-box; }
body { margin: 0; font: 14px/1.5 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  color: var(--fg); background: var(--bg); }
main { max-width: 980px; margin: 0 auto; padding: 32px 24px 48px; }
h1 { font-size: 24px; margin: 0 0 4px; } h2 { font-size: 18px; margin: 32px 0 12px; }
h3 { font-size: 15px; margin: 0; } h4 { font-size: 13px; margin: 16px 0 6px; text-transform: uppercase;
  letter-spacing: .04em; color: var(--muted); }
.meta { color: var(--muted); font-size: 13px; }
.top { display: flex; gap: 24px; align-items: center; justify-content: space-between; flex-wrap: wrap;
  border-bottom: 1px solid var(--line); padding-bottom: 20px; }
.grade { width: 84px; height: 84px; border-radius: 16px; display: flex; flex-direction: column;
  align-items: center; justify-content: center; color: #fff; font-weight: 700; }
.grade b { font-size: 40px; line-height: 1; } .grade span { font-size: 11px; opacity: .9; }
.g-A { background: #1f7a3f; } .g-B { background: #4d8a1e; } .g-C { background: #b7791f; }
.g-D { background: #d9480f; } .g-F { background: #b42318; }
.cards { display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; margin-top: 16px; }
.card { border: 1px solid var(--line); border-radius: 10px; padding: 10px 12px; background: var(--panel); }
.card b { display: block; font-size: 22px; } .card span { font-size: 12px; color: var(--muted); text-transform: capitalize; }
.bar { display: flex; height: 10px; border-radius: 6px; overflow: hidden; background: var(--line); margin-top: 12px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 600; }
.pill { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 11px; font-weight: 700;
  color: #fff; text-transform: uppercase; letter-spacing: .03em; }
.s-critical { background: var(--critical); } .s-high { background: var(--high); }
.s-medium { background: var(--medium); } .s-low { background: var(--low); } .s-info { background: var(--info); }
.finding { border: 1px solid var(--line); border-radius: 12px; padding: 16px 18px; margin: 14px 0;
  break-inside: avoid; page-break-inside: avoid; }
.finding header { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.loc { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12.5px; color: var(--muted); }
.kv { display: flex; gap: 16px; flex-wrap: wrap; font-size: 12px; color: var(--muted); margin-top: 6px; }
pre { background: var(--code-bg); color: var(--code-fg); padding: 10px 12px; border-radius: 8px;
  overflow-x: auto; font: 12px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  white-space: pre-wrap; word-break: break-word; margin: 6px 0; }
.tk { color: #c4b5fd; } .ts { color: #86efac; } .tn { color: #fbbf24; } .tc { color: #94a3b8; font-style: italic; }
.cols { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
.cols .label { font-size: 11px; font-weight: 700; color: var(--muted); text-transform: uppercase; }
ol { margin: 6px 0 0 20px; padding: 0; } li { margin: 2px 0; }
.note { background: #fff8e6; border: 1px solid #f3dca2; border-radius: 8px; padding: 8px 10px; font-size: 13px; }
.evidence { font-size: 13px; color: var(--muted); }
a { color: #2f6fb0; }
footer { margin-top: 40px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--line); padding-top: 12px; }
@media print { main { padding: 0; } h2 { break-after: avoid; } a { color: inherit; } }
@page { margin: 16mm 14mm; }
`;

function pct(n: number): string {
  return `${Math.round(n * 100)}%`;
}

function renderFinding(f: Finding, index: number): string {
  const r = f.remediation;
  const ex = r?.secureExample;
  const lines = f.lineStart === f.lineEnd ? `${f.lineStart}` : `${f.lineStart}-${f.lineEnd}`;
  return `
<article class="finding" id="f${index + 1}">
  <header>
    <span class="pill s-${f.severity}">${e(f.severity)}</span>
    <h3>${index + 1}. ${e(r?.title ?? f.detectorId)}</h3>
  </header>
  <div class="loc">${e(f.filePath)}:${lines}</div>
  <div class="kv">
    <span>${e(f.owaspCategory)}</span>${f.cwe ? `<span>${e(f.cwe)}</span>` : ''}
    <span>Confidence ${pct(f.confidence)}</span>
    <span>Detector: ${e(f.contributingDetectors.join(', '))}</span>
  </div>
  <pre>${highlight(f.snippet, ex?.language ?? 'typescript')}</pre>
  ${f.evidence.map((ev) => `<p class="evidence">${e(ev)}</p>`).join('')}
  <h4>Why it's vulnerable</h4><p>${e(r?.why ?? f.explanation)}</p>
  ${r ? `<h4>Impact</h4><p>${e(r.impact)}</p>` : ''}
  ${r ? `<h4>How to fix</h4><ol>${r.steps.map((s) => `<li>${e(s)}</li>`).join('')}</ol>` : `<h4>How to fix</h4><p>${e(f.fixSuggestion)}</p>`}
  ${
    ex
      ? `<h4>Secure example${ex.contextualized ? ' (from your code)' : ''}</h4>
  <div class="cols">
    <div><div class="label">Before</div><pre>${highlight(ex.before, ex.language)}</pre></div>
    <div><div class="label">After</div><pre>${highlight(ex.after, ex.language)}</pre></div>
  </div>
  ${ex.note ? `<p class="note">${e(ex.note)}</p>` : ''}`
      : ''
  }
  ${r?.references.length ? `<h4>References</h4><ul>${r.references.map((ref) => `<li><a href="${e(ref.url)}">${e(ref.title)}</a></li>`).join('')}</ul>` : ''}
</article>`;
}

/** "node_modules, dist" — at most 4 names, then "+N more". */
function skippedDirsLabel(dirs: string[]): string {
  return dirs.length > 4
    ? `${dirs.slice(0, 4).join(', ')} +${dirs.length - 4} more`
    : dirs.join(', ');
}

export function renderReportHtml(report: ScanReport): string {
  const { rollup } = report;
  const total = Math.max(rollup.total, 1);
  const bar = SEVERITIES.filter((s) => rollup.bySeverity[s] > 0)
    .map((s) => `<div class="s-${s}" style="width:${(rollup.bySeverity[s] / total) * 100}%"></div>`)
    .join('');
  const categories = Object.entries(rollup.byOwaspCategory).sort(
    (a, b) => (b[1] ?? 0) - (a[1] ?? 0),
  );
  const weights = Object.entries(RISK_MODEL.severityWeights)
    .map(([s, w]) => `${s} ${w}`)
    .join(', ');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<title>WebGuard report: ${e(report.project.name)}</title>
<style>${CSS}</style>
</head>
<body>
<main>
  <section class="top">
    <div>
      <h1>Security report: ${e(report.project.name)}</h1>
      <div class="meta">Scan ${e(report.scan.id)} · finished ${e(report.scan.finishedAt ?? report.scan.createdAt)} · generated ${e(report.generatedAt)}</div>
      ${
        report.profile
          ? `<div class="meta">${e(report.profile.languages.map((l) => `${l.language} (${l.files})`).join(', '))}${report.profile.frameworks.length ? ` · ${e(report.profile.frameworks.map((f) => f.name).join(', '))}` : ''} · ${report.profile.filesParsed} files parsed${report.profile.skippedFileCount ? ` · ignored ${report.profile.skippedFileCount} dependency/build files (${e(skippedDirsLabel(report.profile.skippedDirs))})` : ''}</div>`
          : ''
      }
    </div>
    <div class="grade g-${rollup.grade}"><b>${rollup.grade}</b><span>risk ${rollup.riskScore}/100</span></div>
  </section>

  <h2>Summary</h2>
  <p>${rollup.total} finding${rollup.total === 1 ? '' : 's'}. ${e(rollup.gradeReason)}.</p>
  <div class="cards">${SEVERITIES.map((s) => `<div class="card"><b>${rollup.bySeverity[s]}</b><span>${s}</span></div>`).join('')}</div>
  <div class="bar">${bar}</div>

  ${
    categories.length
      ? `<h2>By OWASP category</h2>
  <table><thead><tr><th>Category</th><th>Findings</th></tr></thead><tbody>
  ${categories.map(([c, n]) => `<tr><td>${e(c)}</td><td>${n}</td></tr>`).join('')}
  </tbody></table>`
      : ''
  }

  <h2>Findings</h2>
  ${report.findings.length ? report.findings.map(renderFinding).join('') : '<p>No findings.</p>'}

  <h2>Review manually (informational)</h2>
  <p class="meta">These weakness classes are not code defects detectable from source; they are listed so they are not overlooked.</p>
  <table><thead><tr><th>Item</th><th>References</th><th>How to check</th></tr></thead><tbody>
  ${report.informationalNotes.map((n) => `<tr><td>${e(n.title)}</td><td>${e(n.references.join(', '))}</td><td>${e(n.note)}</td></tr>`).join('')}
  </tbody></table>

  <footer>
    Generated by WebGuard. Risk score = 100 × (1 − e^(−Σ weight × confidence / ${RISK_MODEL.saturation})), weights: ${e(weights)};
    a critical finding with confidence ≥ ${RISK_MODEL.criticalCap.minConfidence} caps the grade at ${RISK_MODEL.criticalCap.worstAllowedBest}.
    Detectors: ${e(report.detectors.join(', ') || 'n/a')}.
    ${report.detectorErrors.length ? `Detector errors: ${e(report.detectorErrors.map((d) => `${d.detectorId}: ${d.message}`).join('; '))}.` : ''}
  </footer>
</main>
</body>
</html>`;
}
