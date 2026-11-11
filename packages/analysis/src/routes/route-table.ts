import { textOf, walk } from '../ast/queries.js';
import { resolveValues } from '../ast/taint.js';
import type { AstNode, ParsedFile } from '../ast/types.js';
import type { DetectionContext } from '../detection/types.js';

/**
 * Lightweight route model for Express (and Express-style routers) and NestJS controllers.
 *
 * Built once per scan from the ASTs and shared by every route-aware detector. It is
 * best-effort: routes registered dynamically (computed paths, loops over route tables)
 * are not recovered, and a cross-file mount (`app.use('/api', auth, router)`) is matched to
 * the router's file by module name.
 */

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'ALL' | 'OPTIONS' | 'HEAD';
export type AuthMechanism = 'cookie-session' | 'bearer' | 'none';

export interface Middleware {
  /** Source text, shortened: `security.isAuthorized()`, `requireLogin`. */
  name: string;
  /** Inherited from `app.use(...)` / a router mount / a Nest class decorator. */
  inherited: boolean;
  /** Session/body-parser/security-header setup, not an access check. */
  infrastructure: boolean;
}

export interface RouteEntry {
  framework: 'express' | 'nest';
  method: HttpMethod;
  path: string;
  /** Where the route is registered. */
  file: ParsedFile;
  node: AstNode;
  middlewareChain: Middleware[];
  /** The handler function, when it could be resolved (inline, local, or via a factory). */
  handlerNode?: AstNode;
  handlerFile?: ParsedFile;
  authMechanism: AuthMechanism;
  /** Authenticated by any middleware, or inline in the handler. */
  authenticated: boolean;
  /** A role/permission check (admin guard, `hasRole`, ...) is present. */
  hasAuthorization: boolean;
  csrfProtected: boolean;
}

export interface RouteTable {
  routes: RouteEntry[];
  /** express-session / cookie-session / passport.session() is used somewhere. */
  usesSessions: boolean;
  /** SameSite configured on the session cookie (`lax` / `strict` protect against CSRF). */
  sessionSameSite?: 'lax' | 'strict' | 'none';
}

const HTTP_METHODS = new Set(['get', 'post', 'put', 'patch', 'delete', 'all', 'options', 'head']);
const ROUTER_RECEIVER = /^(app|router|server|api|routes?|\w*Router|\w*App|\w*Routes)$/i;

const AUTH_MW =
  /auth|login|logged|verify|jwt|bearer|token|passport|guard|protect|requireUser|ensure|session|isAuthorized|isAdmin|role|permission/i;
const BEARER_MW =
  /jwt|bearer|token|isAuthorized|expressJwt|AuthGuard\(\s*['"`]?jwt|passport\.authenticate\(\s*['"`](jwt|bearer)/i;
const SESSION_MW =
  /session|isAuthenticated|ensureLoggedIn|ensureAuthenticated|requireLogin|loggedIn|cookie|passport\.authenticate\(\s*['"`]local/i;
const ROLE_MW =
  /admin|role|permission|privilege|authoriz(e|ation)(?!d)|hasRole|checkRole|isAccounting|PoliciesGuard|\bcan[A-Z]\w*/i;
/** Session/body-parsing setup: infrastructure, not an authentication check. */
const INFRA_MW =
  /^(express\.\w+|bodyParser\.\w+|cookieParser|helmet|cors|compression|morgan|(express)?[sS]ession|cookieSession|passport\.(initialize|session))\s*\(/;
const CSRF_MW = /csrf|csurf|xsrf|lusca/i;

const INLINE_COOKIE_AUTH =
  /req\.(cookies|signedCookies)\.(token|session|auth|jwt|sid|access\w*)|req\.session\b/;
const INLINE_BEARER_AUTH =
  /req\.headers\.authorization|req\.(get|header)\(\s*['"]authorization['"]\s*\)|Bearer\s/i;
const INLINE_AUTH_CHECK =
  /req\.(user|session|auth|isAuthenticated)\b|jwt\.verify\(|\.isAuthorized\(|authenticatedUsers\.(get|from)|verifyToken\(/;

function literal(node: AstNode | undefined): string | undefined {
  if (!node) return undefined;
  for (const v of resolveValues(node)) {
    if (v.type === 'StringLiteral') return v.value;
    if (v.type === 'TemplateLiteral' && v.value !== undefined) return v.value;
  }
  return undefined;
}

function shortText(file: ParsedFile, node: AstNode): string {
  const t = textOf(file, node).replace(/\s+/g, ' ').trim();
  return t.length > 80 ? `${t.slice(0, 79)}…` : t;
}

function moduleBase(path: string): string {
  return path
    .split('/')
    .at(-1)!
    .replace(/\.[cm]?[jt]sx?$/, '');
}

function joinPath(prefix: string, sub: string): string {
  const joined = `/${prefix}/${sub}`.replace(/\/+/g, '/');
  return joined.length > 1 ? joined.replace(/\/$/, '') : joined;
}

/** Function index across the project: name → function nodes (for `retrieveBasket()` factories). */
function indexFunctions(
  files: ParsedFile[],
): Map<string, Array<{ fn: AstNode; file: ParsedFile }>> {
  const index = new Map<string, Array<{ fn: AstNode; file: ParsedFile }>>();
  const add = (name: string | undefined, fn: AstNode, file: ParsedFile) => {
    if (!name) return;
    const list = index.get(name) ?? [];
    list.push({ fn, file });
    index.set(name, list);
  };
  for (const file of files) {
    for (const n of walk(file)) {
      if (n.type !== 'Function') continue;
      add(n.name, n, file);
      const parent = n.parent;
      if (parent?.type === 'Assignment' && parent.right === n)
        add(parent.name?.split('.').at(-1), n, file);
    }
  }
  return index;
}

/** If `fn` is a factory (`function retrieveBasket() { return (req, res) => … }`), the inner handler. */
function unwrapFactory(fn: AstNode): AstNode {
  const params = (fn.raw as { params?: unknown[] }).params ?? [];
  if (params.length >= 2) return fn; // already (req, res, ...)
  for (const n of walk(fn)) {
    if (n === fn) continue;
    if (n.type === 'Return' && n.children[0]?.type === 'Function') return n.children[0];
  }
  // Arrow with expression body: `() => (req, res) => …`
  const body = fn.children.at(-1);
  if (body?.type === 'Function') return body;
  return fn;
}

function resolveHandler(
  node: AstNode,
  file: ParsedFile,
  functions: ReturnType<typeof indexFunctions>,
): { fn: AstNode; file: ParsedFile } | undefined {
  if (node.type === 'Function') return { fn: node, file };
  if (node.type === 'Identifier') {
    const local = resolveValues(node).find((v) => v.type === 'Function');
    if (local) return { fn: local, file };
    const named = functions.get(node.name ?? '');
    const same = named?.find((f) => f.file === file) ?? named?.[0];
    return same ? { fn: same.fn, file: same.file } : undefined;
  }
  if (node.type === 'Call') {
    const name = node.name?.split('.').at(-1);
    const candidates = name ? functions.get(name) : undefined;
    const target = candidates?.find((c) => c.file === file) ?? candidates?.[0];
    return target ? { fn: unwrapFactory(target.fn), file: target.file } : undefined;
  }
  return undefined;
}

interface UseEntry {
  file: ParsedFile;
  line: number;
  prefix?: string;
  middlewares: string[];
  /** Router module mounted by this `use`, if the last argument is an imported router. */
  mountedModule?: string;
}

function importedModuleBase(file: ParsedFile, identifier: string): string | undefined {
  const re = new RegExp(
    `(?:import\\s+(?:\\*\\s+as\\s+)?${identifier}\\s+from|(?:const|let|var)\\s+${identifier}\\s*=\\s*require\\()\\s*['"]([^'"]+)['"]`,
  );
  const m = re.exec(file.sourceText);
  return m?.[1] ? moduleBase(m[1]) : undefined;
}

function classify(
  chain: Middleware[],
  handlerText: string,
  usesSessions: boolean,
): Pick<RouteEntry, 'authMechanism' | 'authenticated' | 'hasAuthorization' | 'csrfProtected'> {
  const names = chain.map((m) => m.name);
  const authMw = names.filter((n) => AUTH_MW.test(n) && !CSRF_MW.test(n) && !INFRA_MW.test(n));
  const hasAuthorization = names.some((n) => ROLE_MW.test(n) && !INFRA_MW.test(n));
  const csrfProtected = names.some((n) => CSRF_MW.test(n));

  let authMechanism: AuthMechanism = 'none';
  if (authMw.some((n) => BEARER_MW.test(n))) authMechanism = 'bearer';
  else if (authMw.some((n) => SESSION_MW.test(n))) authMechanism = 'cookie-session';
  else if (authMw.length > 0) authMechanism = usesSessions ? 'cookie-session' : 'bearer';
  else if (INLINE_COOKIE_AUTH.test(handlerText)) authMechanism = 'cookie-session';
  else if (INLINE_BEARER_AUTH.test(handlerText)) authMechanism = 'bearer';

  const authenticated =
    authMw.length > 0 ||
    hasAuthorization ||
    authMechanism !== 'none' ||
    INLINE_AUTH_CHECK.test(handlerText);
  return { authMechanism, authenticated, hasAuthorization, csrfProtected };
}

function sessionConfig(files: ParsedFile[]): Pick<RouteTable, 'usesSessions' | 'sessionSameSite'> {
  let usesSessions = false;
  let sessionSameSite: RouteTable['sessionSameSite'];
  for (const file of files) {
    if (
      /from\s+['"](express-session|cookie-session)['"]|require\(\s*['"](express-session|cookie-session)['"]\s*\)|passport\.session\(/.test(
        file.sourceText,
      )
    ) {
      usesSessions = true;
    }
    for (const n of walk(file)) {
      if (n.type !== 'Property') continue;
      const key = (n.raw as { key?: { name?: string; value?: string } }).key;
      if ((key?.name ?? key?.value) !== 'sameSite') continue;
      const value = n.children.at(-1);
      const v =
        value?.type === 'StringLiteral'
          ? value.value?.toLowerCase()
          : value?.rawType === 'BooleanLiteral'
            ? String((value.raw as { value: boolean }).value)
            : undefined;
      // Only session-cookie config counts (session({ cookie: { sameSite } }) / cookieSession({ sameSite })).
      if (!isInsideSessionCall(n)) continue;
      if (v === 'strict' || v === 'true') sessionSameSite = 'strict';
      else if (v === 'lax' && sessionSameSite !== 'strict') sessionSameSite = 'lax';
      else if (v === 'none' && !sessionSameSite) sessionSameSite = 'none';
    }
  }
  return { usesSessions, sessionSameSite };
}

function isInsideSessionCall(node: AstNode): boolean {
  for (let p = node.parent; p; p = p.parent) {
    if (p.type === 'Call')
      return /(^|\.)(session|expressSession|cookieSession)$/.test(p.name ?? '');
  }
  return false;
}

// ---------------------------------------------------------------------------
// Express
// ---------------------------------------------------------------------------

function expressRoutes(
  files: ParsedFile[],
  functions: ReturnType<typeof indexFunctions>,
  usesSessions: boolean,
): RouteEntry[] {
  const uses: UseEntry[] = [];
  const raw: Array<
    Omit<RouteEntry, 'authMechanism' | 'authenticated' | 'hasAuthorization' | 'csrfProtected'>
  > = [];

  for (const file of files) {
    for (const call of walk(file)) {
      if (call.type !== 'Call' || call.callee?.type !== 'MemberAccess') continue;
      const method = call.callee.property ?? '';
      const receiver = call.callee.object;
      const args = call.arguments ?? [];

      if (
        method === 'use' &&
        receiver &&
        ROUTER_RECEIVER.test(receiver.name?.split('.').at(-1) ?? '')
      ) {
        const prefix = literal(args[0]);
        const rest = prefix !== undefined ? args.slice(1) : args;
        const last = rest.at(-1);
        const mounted =
          last?.type === 'Identifier' ? importedModuleBase(file, last.name ?? '') : undefined;
        uses.push({
          file,
          line: call.loc.startLine,
          prefix,
          middlewares: (mounted ? rest.slice(0, -1) : rest).map((m) => shortText(file, m)),
          mountedModule: mounted,
        });
        continue;
      }
      if (!HTTP_METHODS.has(method) || args.length < 2) continue;

      // router.route('/x').get(handler)
      let path: string | undefined;
      let handlers = args;
      if (receiver?.type === 'Call' && receiver.callee?.property === 'route') {
        path = literal(receiver.arguments?.[0]);
      } else if (receiver && ROUTER_RECEIVER.test(receiver.name?.split('.').at(-1) ?? '')) {
        path = literal(args[0]);
        handlers = args.slice(1);
      }
      if (path === undefined || !/^[/*]/.test(path) || handlers.length === 0) continue;

      const handlerArg = handlers.at(-1)!;
      const resolved = resolveHandler(handlerArg, file, functions);
      raw.push({
        framework: 'express',
        method: method.toUpperCase() as HttpMethod,
        path,
        file,
        node: call,
        middlewareChain: handlers.slice(0, -1).map((m) => ({
          name: shortText(file, m),
          inherited: false,
          infrastructure: INFRA_MW.test(shortText(file, m)),
        })),
        handlerNode: resolved?.fn,
        handlerFile: resolved?.file,
      });
    }
  }

  return raw.map((r) => {
    const inherited: Middleware[] = [];
    let path = r.path;
    // app.use([prefix], ...mw) earlier in the same file, applying to this path.
    for (const u of uses) {
      if (u.mountedModule) continue;
      if (u.file !== r.file || u.line >= r.node.loc.startLine) continue;
      if (u.prefix && !r.path.startsWith(u.prefix)) continue;
      for (const m of u.middlewares)
        inherited.push({ name: m, inherited: true, infrastructure: INFRA_MW.test(m) });
    }
    // app.use('/api', auth, usersRouter) mounting this file's router.
    for (const u of uses) {
      if (!u.mountedModule || u.mountedModule !== moduleBase(r.file.path)) continue;
      if (u.prefix) path = joinPath(u.prefix, r.path);
      for (const m of u.middlewares)
        inherited.push({ name: m, inherited: true, infrastructure: INFRA_MW.test(m) });
      // Middleware registered in the mounting file before the mount also applies.
      for (const g of uses) {
        if (g.file === u.file && !g.mountedModule && !g.prefix && g.line < u.line) {
          for (const m of g.middlewares)
            inherited.push({ name: m, inherited: true, infrastructure: INFRA_MW.test(m) });
        }
      }
    }
    const chain = [...inherited, ...r.middlewareChain];
    const handlerText = r.handlerNode && r.handlerFile ? textOf(r.handlerFile, r.handlerNode) : '';
    return { ...r, path, middlewareChain: chain, ...classify(chain, handlerText, usesSessions) };
  });
}

// ---------------------------------------------------------------------------
// NestJS
// ---------------------------------------------------------------------------

type RawDecorator = {
  expression?: {
    type: string;
    callee?: { name?: string };
    arguments?: Array<{ type: string; value?: string }>;
  };
};

function decorators(node: AstNode): Array<{ name: string; arg?: string }> {
  const list = (node.raw as { decorators?: RawDecorator[] }).decorators ?? [];
  return list.flatMap((d) => {
    const e = d.expression;
    if (e?.type !== 'CallExpression' || !e.callee?.name) return [];
    const first = e.arguments?.[0];
    return [
      { name: e.callee.name, arg: first?.type === 'StringLiteral' ? first.value : undefined },
    ];
  });
}

const NEST_METHODS: Record<string, HttpMethod> = {
  Get: 'GET', Post: 'POST', Put: 'PUT', Patch: 'PATCH', Delete: 'DELETE', All: 'ALL', Options: 'OPTIONS', Head: 'HEAD',
}; // prettier-ignore

function guardsText(file: ParsedFile, node: AstNode): string[] {
  // Render @UseGuards(...) decorators from source text by line.
  const raw =
    (
      node.raw as {
        decorators?: Array<{
          start: number;
          end: number;
          expression?: { callee?: { name?: string } };
        }>;
      }
    ).decorators ?? [];
  return raw
    .filter((d) =>
      ['UseGuards', 'Roles', 'UseInterceptors'].includes(d.expression?.callee?.name ?? ''),
    )
    .map((d) => file.sourceText.slice(d.start + 1, d.end).replace(/\s+/g, ' '));
}

function nestRoutes(files: ParsedFile[], usesSessions: boolean): RouteEntry[] {
  const routes: RouteEntry[] = [];
  for (const file of files) {
    if (!/@nestjs\/common/.test(file.sourceText)) continue;
    for (const cls of walk(file)) {
      if (cls.rawType !== 'ClassDeclaration') continue;
      const controller = decorators(cls).find((d) => d.name === 'Controller');
      if (!controller) continue;
      const classGuards = guardsText(file, cls).map((name) => ({
        name,
        inherited: true,
        infrastructure: false,
      }));
      for (const member of walk(cls)) {
        if (member.rawType !== 'ClassMethod') continue;
        const route = decorators(member).find((d) => NEST_METHODS[d.name]);
        if (!route) continue;
        const chain = [
          ...classGuards,
          ...guardsText(file, member).map((name) => ({
            name,
            inherited: false,
            infrastructure: false,
          })),
        ];
        routes.push({
          framework: 'nest',
          method: NEST_METHODS[route.name]!,
          path: joinPath(controller.arg ?? '', route.arg ?? ''),
          file,
          node: member,
          middlewareChain: chain,
          handlerNode: member,
          handlerFile: file,
          ...classify(chain, textOf(file, member), usesSessions),
        });
      }
    }
  }
  return routes;
}

// ---------------------------------------------------------------------------

const cache = new WeakMap<DetectionContext, RouteTable>();

export function buildRouteTable(ctx: DetectionContext): RouteTable {
  const files = ctx.files.filter((f): f is ParsedFile & { ast: AstNode } => f.ast !== null);
  const session = sessionConfig(files);
  const functions = indexFunctions(files);
  return {
    routes: [
      ...expressRoutes(files, functions, session.usesSessions),
      ...nestRoutes(files, session.usesSessions),
    ],
    ...session,
  };
}

/** The scan's route table, built on first use and shared by all detectors. */
export function getRouteTable(ctx: DetectionContext): RouteTable {
  let table = cache.get(ctx);
  if (!table) {
    table = buildRouteTable(ctx);
    cache.set(ctx, table);
  }
  return table;
}

export const isStateChanging = (method: HttpMethod) =>
  method === 'POST' ||
  method === 'PUT' ||
  method === 'PATCH' ||
  method === 'DELETE' ||
  method === 'ALL';
