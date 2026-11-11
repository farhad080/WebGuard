import { findAll, matchesName, textOf, walk } from '../../ast/queries.js';
import { parameterNames } from '../../ast/taint.js';
import type { AstNode, ParsedFile } from '../../ast/types.js';
import { getRouteTable } from '../../routes/route-table.js';
import { registerDetector } from '../registry.js';
import type { RawFinding } from '../types.js';
import { findingAt, parsedFiles, shorten } from './shared.js';

/**
 * A12 — Security misconfiguration (AST + config).
 *
 *  1. Verbose errors: an Express error handler (4 params, `(err, req, res, next)`) that sends
 *     `err.stack` / the raw error to the client, or `app.use(errorhandler())`, not gated
 *     behind a NODE_ENV / environment check. High. Juice Shop #36.
 *  2. Missing security headers: an Express app without `helmet()` and without equivalents
 *     for Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options. Medium.
 *  3. Directory listing (`serveIndex`), medium; it correlates with A7's finding (same CWE).
 *  4. Deprecated / legacy routes still mounted: a route registration marked deprecated /
 *     legacy / removed in an adjacent comment or its path, or an upload route that still
 *     parses XML (Juice Shop #37's B2B XML interface). Medium, low confidence.
 *  5. No `/.well-known/security.txt` (file, route, or middleware). Low hygiene note. Juice Shop #35.
 *
 * Headers, listing and security.txt are often configured at the proxy / CDN / deploy layer,
 * which source analysis cannot see; those findings say so.
 */

const CATEGORY = 'A02:2025-Security Misconfiguration' as const;
const ENV_GATE =
  /NODE_ENV|production|development|isProd|isDev|app\.get\(\s*['"]env['"]\s*\)|IS_PROD|DEBUG/;
const DEPRECATED_TEXT =
  /deprecat|legacy|obsolete|no longer (used|supported)|to be removed|removed from|do not use/i;
const XML_PARSING = /parseXml|parseXmlString|xml2js|libxmljs|DOMParser|fast-xml-parser|XMLParser/;

const PROXY_NOTE =
  ' (Headers can also be set by a reverse proxy, CDN, or platform, which is invisible to ' +
  'source analysis; confirm against a live response.)';

const EXPLAIN = {
  errors:
    'Error details (stack traces, raw error objects) are sent to the client. They reveal ' +
    'file paths, framework versions, SQL and internal logic that help an attacker craft the ' +
    'next exploit, e.g. a stack trace showing the exact query that failed.',
  headers:
    'Standard security headers are not set by the application: without Content-Security-' +
    'Policy, injected scripts run freely; without HSTS, users can be downgraded to HTTP; ' +
    'without X-Content-Type-Options: nosniff, browsers may execute uploaded files as scripts.' +
    PROXY_NOTE,
  listing:
    'Directory listing is enabled, so anyone can browse every file in the directory and ' +
    'find backups and documents that were never linked.',
  deprecated:
    'Low confidence: an interface that appears deprecated or legacy is still registered. ' +
    'Forgotten endpoints rarely get security fixes and are a favourite attack surface (e.g. ' +
    'an old XML upload that still parses external entities).',
  securityTxt:
    'Hygiene: the project has no /.well-known/security.txt, so researchers have no documented ' +
    'way to report vulnerabilities (RFC 9116). It may be served by the web server or CDN ' +
    'instead, which source analysis cannot see.',
};
const FIX = {
  errors:
    'Return a generic error message to clients and log details server-side; enable verbose ' +
    'handlers (errorhandler, stack output) only when NODE_ENV === "development".',
  headers:
    'Add helmet() (or set Content-Security-Policy, Strict-Transport-Security and ' +
    'X-Content-Type-Options yourself) for every response.',
  listing: 'Remove serveIndex / directory listing and serve only an explicit public directory.',
  deprecated:
    'Remove the deprecated route (and its handler) from the server, or protect it like any ' +
    'current endpoint; for XML, disable external entities (noent: false).',
  securityTxt:
    'Publish /.well-known/security.txt with Contact and Expires fields (e.g. via the ' +
    'express-security.txt middleware or a static file).',
};

/** Is `node` inside an if / ternary / && whose condition checks the environment? */
function envGated(file: ParsedFile, node: AstNode): boolean {
  for (let p = node.parent; p; p = p.parent) {
    if (p.rawType === 'IfStatement' || p.rawType === 'ConditionalExpression') {
      const test = p.children[0];
      if (test && ENV_GATE.test(textOf(file, test))) return true;
    }
    if (p.type === 'Binary' && p.operator === '&&' && p.left && ENV_GATE.test(textOf(file, p.left)))
      return true;
    if (p.type === 'Function' && p.parent?.type === 'Call' && p.parent.callee?.property !== 'use')
      break;
  }
  return false;
}

/** `(err, req, res, next) => …` registered with app.use. */
function errorHandlers(file: ParsedFile): Array<{ fn: AstNode; err: string; res: string }> {
  const out: Array<{ fn: AstNode; err: string; res: string }> = [];
  for (const fn of walk(file)) {
    if (fn.type !== 'Function') continue;
    const params = parameterNames(fn);
    if (params.length !== 4 || !/^(err|error|e|ex)$/i.test(params[0] ?? '')) continue;
    out.push({ fn, err: params[0]!, res: params[2]! });
  }
  return out;
}

export const securityMisconfig = registerDetector({
  id: 'A12-security-misconfig',
  title: 'Security misconfiguration',
  owaspCategory: CATEGORY,
  cwe: 'CWE-16',
  technique: 'config',
  explanation: EXPLAIN.errors,
  fixSuggestion: FIX.errors,

  run(ctx) {
    const findings: RawFinding[] = [];
    const files = parsedFiles(ctx);
    const push = (
      file: ParsedFile,
      node: AstNode,
      kind: keyof typeof EXPLAIN,
      severity: RawFinding['severity'],
      confidence: number,
      evidence: string,
      cwe: string,
    ) =>
      findings.push(
        findingAt(ctx, file, node, {
          detectorId: 'A12-security-misconfig',
          owaspCategory: CATEGORY,
          severity,
          confidence,
          evidence,
          explanation: EXPLAIN[kind],
          fixSuggestion: FIX[kind],
          cwe,
        }),
      );

    const appCreations: Array<{ file: ParsedFile; node: AstNode }> = [];
    let helmetFull = false;
    const headerHints = { csp: false, hsts: false, nosniff: false };

    for (const file of files) {
      const text = file.sourceText;
      // ---- 1. Verbose error handlers ----
      for (const { fn, err, res } of errorHandlers(file)) {
        for (const call of walk(fn)) {
          if (call.type !== 'Call' || call.callee?.type !== 'MemberAccess') continue;
          if (
            !['send', 'json', 'end', 'write', 'render', 'jsonp'].includes(
              call.callee.property ?? '',
            )
          )
            continue;
          if (!new RegExp(`^${res}\\b`).test(call.name ?? textOf(file, call.callee))) {
            if (!textOf(file, call.callee).startsWith(res)) continue;
          }
          const args = (call.arguments ?? []).map((a) => textOf(file, a)).join(', ');
          const leaksStack = new RegExp(`\\b${err}\\.stack\\b`).test(args);
          const leaksRaw = new RegExp(`(^|[^.\\w])${err}($|[^.\\w])`).test(args);
          if (!leaksStack && !leaksRaw) continue;
          if (envGated(file, call)) continue;
          push(
            file,
            call,
            'errors',
            'high',
            0.8,
            `error handler sends ${leaksStack ? `${err}.stack` : `the raw ${err} object`} to the client: ${shorten(textOf(file, call), 80)}`,
            'CWE-209',
          );
        }
      }
      for (const call of findAll(file, (n) => n.type === 'Call')) {
        const name = call.name ?? '';
        // errorhandler() middleware renders full stack traces.
        if (
          name === 'errorhandler' ||
          (name === 'errorHandler' &&
            /require\(\s*['"]errorhandler['"]|from\s+['"]errorhandler['"]/.test(text))
        ) {
          if (!envGated(file, call)) {
            push(
              file,
              call,
              'errors',
              'high',
              0.85,
              'errorhandler() middleware is enabled without an environment check; it renders full stack traces to clients',
              'CWE-209',
            );
          }
        }
        // ---- 2. Headers: collect evidence ----
        if (name === 'express' || (matchesName(name, '*.create') && /NestFactory/.test(name)))
          appCreations.push({ file, node: call });
        if (name === 'helmet') helmetFull = true;
        if (/^helmet\.(contentSecurityPolicy|csp)$/.test(name)) headerHints.csp = true;
        if (name === 'helmet.hsts') headerHints.hsts = true;
        if (name === 'helmet.noSniff') headerHints.nosniff = true;
        // ---- 3. Directory listing ----
        if (
          name === 'serveIndex' ||
          matchesName(name, '*.serveIndex') ||
          name === 'express.directory'
        ) {
          push(
            file,
            call,
            'listing',
            'medium',
            0.9,
            `directory listing enabled via ${shorten(textOf(file, call), 60)}`,
            'CWE-548',
          );
        }
      }
      if (/Content-Security-Policy/i.test(text)) headerHints.csp = true;
      if (/Strict-Transport-Security/i.test(text)) headerHints.hsts = true;
      if (/X-Content-Type-Options/i.test(text)) headerHints.nosniff = true;
    }

    // ---- 2. Missing security headers ----
    const firstApp = appCreations[0];
    if (firstApp && !helmetFull) {
      const missing = [
        !headerHints.csp && 'Content-Security-Policy',
        !headerHints.hsts && 'Strict-Transport-Security',
        !headerHints.nosniff && 'X-Content-Type-Options',
      ].filter((m): m is string => Boolean(m));
      if (missing.length > 0) {
        push(
          firstApp.file,
          firstApp.node,
          'headers',
          'medium',
          0.6,
          `no helmet() and no ${missing.join(', ')} set in application code`,
          'CWE-693',
        );
      }
    }

    // ---- 4. Deprecated routes still mounted ----
    for (const route of getRouteTable(ctx).routes) {
      const { file, node } = route;
      const before = [node.loc.startLine - 2, node.loc.startLine - 1, node.loc.startLine]
        .filter((l) => l >= 1)
        .map((l) => file.lineIndex.lineText(l))
        .join('\n');
      const handlerText =
        route.handlerNode && route.handlerFile ? textOf(route.handlerFile, route.handlerNode) : '';
      const chainText = route.middlewareChain.map((m) => m.name).join(' ');
      if (DEPRECATED_TEXT.test(before) || /\/(legacy|deprecated|old)(\/|$)/i.test(route.path)) {
        push(
          file,
          node,
          'deprecated',
          'medium',
          0.5,
          `${route.method} ${route.path} is marked deprecated/legacy but still registered`,
          'CWE-912',
        );
      } else if (
        /upload/i.test(route.path) &&
        (/xml/i.test(chainText) || XML_PARSING.test(handlerText))
      ) {
        const xxe =
          /noent\s*:\s*true/.test(handlerText) || /noent\s*:\s*true/.test(file.sourceText)
            ? '; it parses XML with external entities enabled (noent: true)'
            : '';
        push(
          file,
          node,
          'deprecated',
          'medium',
          0.4,
          `${route.method} ${route.path} still accepts XML uploads (a legacy B2B-style interface)${xxe}`,
          'CWE-912',
        );
      }
    }

    // ---- 5. security.txt ----
    const hasSecurityTxt =
      ctx.allFiles.some((f) => /(^|\/)(\.well-known\/)?security\.txt$/i.test(f)) ||
      files.some((f) => /security\.txt|express-security\.txt/.test(f.sourceText));
    // Anchor at app.listen(...) (or line 1) so it never merges with the headers finding.
    const listen = files
      .flatMap((f) =>
        findAll(f, (n) => n.type === 'Call' && n.callee?.property === 'listen').map((node) => ({
          file: f,
          node,
        })),
      )
      .find((l) => !firstApp || l.file === firstApp.file);
    // Only meaningful for a deployed web server (an Express/Nest app was found).
    const entry = firstApp?.file;
    const anchor = entry ? (listen ?? { file: entry, node: entry.ast! }) : undefined;
    if (!hasSecurityTxt && anchor) {
      findings.push({
        detectorId: 'A12-security-misconfig',
        owaspCategory: CATEGORY,
        severity: 'low',
        confidence: 0.7,
        filePath: anchor.file.path,
        lineStart: anchor.node.loc.startLine,
        lineEnd: anchor.node.loc.startLine,
        snippet: ctx.snippet(anchor.file.path, anchor.node.loc.startLine),
        evidence:
          'hygiene: no /.well-known/security.txt file, route, or middleware found in the project',
        explanation: EXPLAIN.securityTxt,
        fixSuggestion: FIX.securityTxt,
        cwe: 'CWE-1059',
      });
    }
    return findings;
  },
});
