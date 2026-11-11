import { matchesName, walk } from './queries.js';
import type { AstNode, NodeTag } from './types.js';

/** A rule that tags matching nodes. Detectors can supply their own rule sets. */
export interface TagRule {
  tag: NodeTag;
  description: string;
  match: (node: AstNode) => boolean;
}

/** Request objects across common Node frameworks (Express/Koa/Fastify/Nest/Next). */
const HTTP_INPUT =
  /^(req|request|ctx\.request|ctx)\.(body|query|params|headers|cookies|signedCookies|files?|rawBody|url|originalUrl|path|hostname|ip)(\.|$)/;

const USER_PROFILE =
  /(^|\.)(user|users|currentUser|loggedInUser|authUser|profile|account|member|customer)\.(username|userName|name|displayName|fullName|firstName|lastName|email|bio|about|description|nickname|title|address)$/;

const CLIENT_URL = new RegExp(
  [
    // location.search / window.location.hash / document.location.href ...
    String.raw`(^|\.)location\.(search|hash|href|pathname)$`,
    String.raw`^(window\.|document\.)?(document\.)?(URL|documentURI|referrer|baseURI)$`,
    String.raw`^window\.name$`,
    // Angular ActivatedRoute: this.route.snapshot.queryParams.q, route.paramMap, ...
    String.raw`(^|\.)(route|activatedRoute|activeRoute)\.(snapshot\.)?(queryParams|params|queryParamMap|paramMap|fragment)(\.|$)`,
  ].join('|'),
);

/**
 * Default source/sink tags.
 * Sources: reads of user-controlled request data (`req.body.x`, `req.query`, `req.headers[..]`).
 * Sinks: a few universally dangerous APIs; detectors add richer, rule-specific sinks.
 *
 * Known limitation (by design for this layer): this is syntactic. Destructuring such as
 * `const { body } = req` and aliasing (`const r = req`) are not followed; that's the job of
 * the data-flow pass built on top of these tags.
 */
export const DEFAULT_TAG_RULES: readonly TagRule[] = [
  {
    tag: 'source:http-input',
    description: 'Reads HTTP request input (body, query, params, headers, cookies, ...)',
    match: (n) => n.type === 'MemberAccess' && !!n.name && HTTP_INPUT.test(n.name),
  },
  {
    // Second-order input: profile fields a user chose earlier (username, bio, ...), read back
    // from a user object. Detectors opt in to this tag where it matters (e.g. SSTI/eval).
    tag: 'source:user-profile',
    description: 'Reads a user-controlled profile field (username, email, bio, ...)',
    match: (n) => n.type === 'MemberAccess' && !!n.name && USER_PROFILE.test(n.name),
  },
  {
    // Browser-side input an attacker controls via a crafted link: URL query/fragment,
    // Angular route params, referrer, window.name.
    tag: 'source:client-url',
    description: 'Reads attacker-controllable URL data in the browser (location, route params)',
    match: (n) => n.type === 'MemberAccess' && !!n.name && CLIENT_URL.test(n.name),
  },
  {
    tag: 'sink:dom-html',
    description: 'Writes HTML into the DOM',
    match: (n) =>
      (n.type === 'Assignment' &&
        n.left?.type === 'MemberAccess' &&
        (n.left.property === 'innerHTML' || n.left.property === 'outerHTML')) ||
      (n.type === 'Call' &&
        ['document.write', 'document.writeln', '*.insertAdjacentHTML'].some((p) =>
          matchesName(n.name, p),
        )),
  },
  {
    tag: 'sink:code-exec',
    description: 'Evaluates a string as code',
    match: (n) =>
      n.type === 'Call' &&
      [
        'eval',
        'Function',
        'setTimeout',
        'setInterval',
        'vm.runInContext',
        'vm.runInNewContext',
        'vm.runInThisContext',
      ].some((p) => matchesName(n.name, p)) &&
      // setTimeout/setInterval are only dangerous with a string argument.
      (!/^set(Timeout|Interval)$/.test(n.name ?? '') ||
        n.arguments?.[0]?.type === 'StringLiteral' ||
        n.arguments?.[0]?.type === 'TemplateLiteral' ||
        n.arguments?.[0]?.type === 'Binary'),
  },
  {
    tag: 'sink:command-exec',
    description: 'Runs an OS command',
    match: (n) =>
      n.type === 'Call' &&
      ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync'].some(
        (fn) =>
          matchesName(n.name, fn) ||
          matchesName(n.name, `child_process.${fn}`) ||
          matchesName(n.name, `cp.${fn}`),
      ),
  },
];

/** Applies tag rules to every node under `root` (idempotent). Returns the number of tags added. */
export function applyTags(
  root: AstNode | null,
  rules: readonly TagRule[] = DEFAULT_TAG_RULES,
): number {
  if (!root) return 0;
  let added = 0;
  for (const node of walk(root)) {
    for (const rule of rules) {
      if (!node.tags.includes(rule.tag) && rule.match(node)) {
        node.tags.push(rule.tag);
        added++;
      }
    }
  }
  return added;
}
