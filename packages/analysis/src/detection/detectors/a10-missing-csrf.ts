import { findAll, textOf } from '../../ast/queries.js';
import { getRouteTable, isStateChanging, type RouteEntry } from '../../routes/route-table.js';
import { registerDetector } from '../registry.js';
import type { RawFinding } from '../types.js';
import { parsedFiles, propertyKey } from './shared.js';

/**
 * A10 — Missing CSRF protection (config, over the RouteTable).
 *
 * Flags state-changing routes (POST/PUT/PATCH/DELETE) that authenticate with a cookie (an
 * express-session / cookie-session session, session-based middleware, or a token read from
 * `req.cookies`) when the route has no CSRF middleware (csurf, lusca, csrf-csrf, …, on the
 * route or via an earlier `app.use`) and the relevant cookie is not `SameSite=Lax/Strict`.
 * Browsers attach cookies to cross-site requests, so a malicious page can submit the form on
 * the victim's behalf. Juice Shop #25 (changing a username via the cookie-authenticated
 * POST /profile).
 *
 * Bearer-token APIs (Authorization header) are excluded: browsers don't attach that header
 * cross-site. Severity medium. Confidence 0.7 for session/cookie middleware, 0.6 when the
 * cookie use is inferred from the handler.
 */

const CATEGORY = 'A01:2025-Broken Access Control' as const;
const SESSION_IN_CHAIN = /session|isAuthenticated|ensureLoggedIn|requireLogin|loggedIn|passport/i;
const INFRA = /^((express)?[sS]ession|cookieSession|passport\.(initialize|session))\s*\(/;
const SESSION_IN_HANDLER = /req\.session\b/;
const COOKIE_TOKEN_IN_HANDLER = /req\.(cookies|signedCookies)\.(\w+)/;

function cookieAuthReason(
  route: RouteEntry,
  handlerText: string,
): { reason: string; confidence: number; cookie?: string } | undefined {
  const sessionMw = route.middlewareChain.find(
    (m) => SESSION_IN_CHAIN.test(m.name) && !INFRA.test(m.name),
  );
  if (sessionMw)
    return { reason: `session-based middleware \`${sessionMw.name}\``, confidence: 0.7 };
  if (SESSION_IN_HANDLER.test(handlerText))
    return { reason: 'req.session in the handler', confidence: 0.7 };
  const cookie = COOKIE_TOKEN_IN_HANDLER.exec(handlerText);
  if (cookie)
    return { reason: `${cookie[0]} read in the handler`, confidence: 0.6, cookie: cookie[2] };
  if (route.authMechanism === 'cookie-session')
    return { reason: 'authentication middleware in a session-based app', confidence: 0.55 };
  return undefined;
}

export const missingCsrf = registerDetector({
  id: 'A10-missing-csrf',
  title: 'Missing CSRF protection',
  owaspCategory: CATEGORY,
  cwe: 'CWE-352',
  technique: 'config',
  explanation:
    'This state-changing route is authenticated by a cookie, has no anti-CSRF token check, and ' +
    'the cookie does not set SameSite=Lax/Strict. A page on any other site can make the ' +
    "victim's browser submit the request with the victim's cookie attached (cross-site " +
    'request forgery), e.g. silently changing their username, email, or password.',
  fixSuggestion:
    'Add CSRF protection (a synchronizer or double-submit token, e.g. csrf-csrf / lusca) to ' +
    'state-changing routes and set the session cookie to SameSite=Lax or Strict (plus Secure, ' +
    'HttpOnly); or authenticate the API with an Authorization: Bearer header instead of cookies.',

  run(ctx) {
    const table = getRouteTable(ctx);
    // SameSite on explicitly set cookies: res.cookie('token', value, { sameSite: 'strict' })
    const cookieSameSite = new Map<string, string>();
    for (const file of parsedFiles(ctx)) {
      for (const call of findAll(
        file,
        (n) => n.type === 'Call' && n.callee?.property === 'cookie',
      )) {
        const [nameArg, , options] = call.arguments ?? [];
        if (nameArg?.type !== 'StringLiteral' || options?.type !== 'Object') continue;
        const same = options.children
          .find((p) => p.type === 'Property' && propertyKey(p) === 'sameSite')
          ?.children.at(-1);
        if (same?.type === 'StringLiteral')
          cookieSameSite.set(nameArg.value ?? '', (same.value ?? '').toLowerCase());
      }
    }

    const findings: RawFinding[] = [];
    for (const route of table.routes) {
      if (!isStateChanging(route.method) || route.authMechanism === 'bearer' || route.csrfProtected)
        continue;
      const handlerText =
        route.handlerNode && route.handlerFile ? textOf(route.handlerFile, route.handlerNode) : '';
      const why = cookieAuthReason(route, handlerText);
      if (!why) continue;

      const sameSite = why.cookie ? cookieSameSite.get(why.cookie) : table.sessionSameSite;
      if (sameSite === 'lax' || sameSite === 'strict') continue;

      const line = route.node.loc.startLine;
      findings.push({
        detectorId: 'A10-missing-csrf',
        owaspCategory: CATEGORY,
        severity: 'medium',
        confidence: why.confidence,
        filePath: route.file.path,
        lineStart: line,
        lineEnd: line,
        snippet: ctx.snippet(route.file.path, line),
        evidence:
          `${route.method} ${route.path} is authenticated by cookie (${why.reason}), has no CSRF middleware, ` +
          `and the ${why.cookie ? `"${why.cookie}"` : 'session'} cookie sets ${sameSite ? `SameSite=${sameSite}` : 'no SameSite attribute'}`,
      });
    }
    return findings;
  },
});
