import { textOf, walk } from '../ast/queries.js';
import { resolveValues, stringParts } from '../ast/taint.js';
import type { AstNode, ParsedFile } from '../ast/types.js';
import type { ContextInput, ContextualExample } from './types.js';

/**
 * Deterministic rewrites of a finding's own code into its secure form. Each function returns
 * undefined when it can't produce a faithful rewrite; the generic template is used instead.
 */

function callsAtLine(
  file: ParsedFile,
  line: number,
  predicate: (n: AstNode) => boolean,
): AstNode[] {
  const out: AstNode[] = [];
  for (const n of walk(file)) {
    if (n.type === 'Call' && n.loc.startLine === line && predicate(n)) out.push(n);
  }
  return out;
}

/** First `backticked` fragment of the evidence: the tainted sub-expression detectors record. */
export function taintedPart(evidence: readonly string[]): string | undefined {
  return /`([^`]+)`/.exec(evidence[0] ?? '')?.[1];
}

const quoteSql = (sql: string) => `'${sql.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;

function constCase(name: string): string {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/[^A-Za-z0-9]+/g, '_')
    .toUpperCase();
}

// ---------------------------------------------------------------------------
// A1: concatenated / interpolated SQL → parameterized query
// ---------------------------------------------------------------------------

type Segment = { lit: string } | { expr: AstNode };

function sqlSegments(expr: AstNode): Segment[] {
  const out: Segment[] = [];
  for (const p of stringParts(expr)) {
    if (p.type === 'StringLiteral') {
      out.push({ lit: p.value ?? '' });
    } else if (p.type === 'TemplateLiteral') {
      const quasis = (p.raw as { quasis: Array<{ value: { cooked: string | null } }> }).quasis;
      const exprs = p.children.filter((c) => c.rawType !== 'TemplateElement');
      quasis.forEach((q, i) => {
        out.push({ lit: q.value.cooked ?? '' });
        const e = exprs[i];
        if (e) out.push({ expr: e });
      });
    } else {
      out.push({ expr: p });
    }
  }
  // merge adjacent literals
  const merged: Segment[] = [];
  for (const s of out) {
    const last = merged.at(-1);
    if (last && 'lit' in last && 'lit' in s) last.lit += s.lit;
    else merged.push({ ...s });
  }
  return merged;
}

/** Rebuilds SQL with placeholders; values keep the user's own expressions. */
function parameterize(
  file: ParsedFile,
  query: AstNode,
  placeholder: (n: number) => string,
): { sql: string; values: string[] } | undefined {
  const segs = sqlSegments(query);
  let sql = '';
  const values: string[] = [];
  for (let i = 0; i < segs.length; i++) {
    const seg = segs[i]!;
    if ('lit' in seg) {
      sql += seg.lit;
      continue;
    }
    const text = textOf(file, seg.expr).replace(/\s+/g, ' ').trim();
    const next = segs[i + 1];
    const nextLit = next && 'lit' in next ? next : undefined;
    const before = /(['"])(%?)$/.exec(sql);
    if (before) {
      const quote = before[1]!;
      const after = nextLit ? new RegExp(`^(%?)${quote}`).exec(nextLit.lit) : null;
      if (!after) return undefined; // quote opened but not closed right after: unsafe to rewrite
      sql = sql.slice(0, -before[0].length);
      nextLit!.lit = nextLit!.lit.slice(after[0].length);
      const lead = before[2] ?? '';
      const trail = after[1] ?? '';
      values.push(lead || trail ? `\`${lead}\${${text}}${trail}\`` : text);
    } else {
      if (nextLit && /^['"]/.test(nextLit.lit)) return undefined;
      values.push(text);
    }
    sql += placeholder(values.length);
  }
  if ((sql.match(/'/g)?.length ?? 0) % 2 !== 0 || values.length === 0) return undefined;
  return { sql: sql.replace(/\s+/g, ' ').trim(), values };
}

export function contextualizeSql({ finding, file }: ContextInput): ContextualExample | undefined {
  if (!file) return undefined;
  const call = callsAtLine(
    file,
    finding.lineStart,
    (n) =>
      !!n.arguments?.[0] &&
      /(^|\.)(query|raw|run|all|get|each|exec|execute|\$queryRawUnsafe|\$executeRawUnsafe)$/.test(
        n.name ?? '',
      ),
  )[0];
  if (!call) return undefined;
  const args = call.arguments!;
  const name = call.name ?? '';
  const callee = textOf(file, call.callee!);
  const style = /sequelize/i.test(name)
    ? 'sequelize'
    : /(^|\.)(pool|client|pg)\./i.test(`${name}`)
      ? 'pg'
      : 'qmark';
  const placeholder = (n: number) => (style === 'qmark' ? '?' : `$${n}`);

  // The query may be built inline or in a variable just above the call.
  const arg0 = args[0]!;
  let query = arg0;
  let variable: { name: string; declLine: string } | undefined;
  if (arg0.type === 'Identifier') {
    const value = resolveValues(arg0).find((v) => v !== arg0);
    if (!value) return undefined;
    query = value;
    variable = { name: arg0.name!, declLine: file.lineIndex.lineText(value.loc.startLine).trim() };
  }
  const built = parameterize(file, query, placeholder);
  if (!built) return undefined;
  const sqlLiteral = quoteSql(built.sql);
  const values = `[${built.values.join(', ')}]`;
  const rest = args.slice(1).map((a) => textOf(file, a).replace(/\s+/g, ' ').trim());

  let call2: string;
  const first = variable ? variable.name : sqlLiteral;
  if (style === 'sequelize') {
    const options = args[1];
    const opts =
      options?.type === 'Object'
        ? textOf(file, options)
            .replace(/\s+/g, ' ')
            .replace(/^\{\s*/, `{ bind: ${values}, `)
            .replace(/, \}$/, ' }')
        : options
          ? `{ ...${rest[0]}, bind: ${values} }`
          : `{ bind: ${values} }`;
    call2 = `${callee}(\n  ${first},\n  ${opts}\n)`;
  } else {
    call2 = `${callee}(${[first, values, ...rest].join(', ')})`;
  }

  const before = variable
    ? `${variable.declLine}\n${finding.snippet.trim()}`
    : finding.snippet.trim();
  const after = variable ? `const ${variable.name} = ${sqlLiteral};\n${call2}` : call2;
  return {
    before,
    after,
    note:
      `Values are sent separately (${style === 'sequelize' ? 'Sequelize `bind`' : style === 'pg' ? '$n placeholders' : '? placeholders'}) ` +
      'and never become part of the SQL text. Any chained calls (.then/.catch) stay unchanged.',
  };
}

// ---------------------------------------------------------------------------
// Text-level rewrites of the flagged snippet
// ---------------------------------------------------------------------------

function rewrite(
  snippet: string,
  transforms: Array<[RegExp, string | ((...m: string[]) => string)]>,
): string | undefined {
  let out = snippet;
  for (const [re, by] of transforms) out = out.replace(re, by as never);
  return out !== snippet ? out : undefined;
}

export function contextualizeNoSql({ finding }: ContextInput): ContextualExample | undefined {
  if (/\$where/.test(finding.evidence[0] ?? '')) return undefined;
  const after = rewrite(finding.snippet, [
    [
      /(\b[\w$]+\s*:\s*)(req\.(?:body|query)\.[\w.]+)(?=\s*[,}])/g,
      (_m, key: string, value: string) => `${key}String(${value})`,
    ],
  ]);
  return after
    ? {
        before: finding.snippet.trim(),
        after: after.trim(),
        note: 'Cast each selector value to the scalar type the field expects (String, Number, or a validated ObjectId).',
      }
    : undefined;
}

export function contextualizeXss({ finding }: ContextInput): ContextualExample | undefined {
  const s = finding.snippet;
  const part = taintedPart(finding.evidence);
  const cls = /^(DOM|Reflected|Stored) XSS/.exec(finding.evidence[0] ?? '')?.[1];
  let after: string | undefined;
  let note = '';
  if (/\.(innerHTML|outerHTML)\s*=/.test(s)) {
    after = rewrite(s, [[/\.(innerHTML|outerHTML)(\s*=)/, '.textContent$2']]);
    note =
      'textContent inserts text, never markup. If HTML is required, use DOMPurify.sanitize(value).';
  } else if (/bypassSecurityTrust(Html|Script|Url|ResourceUrl|Style)\(/.test(s)) {
    after = rewrite(s, [
      [
        /\.bypassSecurityTrust(Html|Script|Url|ResourceUrl|Style)\(/,
        (_m, kind: string) =>
          `.sanitize(SecurityContext.${kind === 'ResourceUrl' ? 'RESOURCE_URL' : kind.toUpperCase()}, `,
      ],
    ]);
    note =
      "Angular's sanitize() strips dangerous markup; or bind the raw value with {{ }} so Angular escapes it.";
  } else if (/dangerouslySetInnerHTML/.test(s)) {
    after = rewrite(s, [[/__html:\s*([^}]+?)\s*\}/, '__html: DOMPurify.sanitize($1) }']]);
    note = 'Prefer rendering plain text ({value}); sanitize only when HTML is genuinely needed.';
  } else if (/\.(send|write|end)\(/.test(s) && part) {
    after = rewrite(s, [
      [
        new RegExp(`(?<![\\w.])${part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![\\w])`, 'g'),
        `escapeHtml(${part})`,
      ],
    ]);
    note = "escapeHtml comes from the 'escape-html' package; or return JSON with res.json().";
  } else if (cls === 'Stored' && part) {
    after = rewrite(s, [
      [
        new RegExp(`(:\\s*)${part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`),
        `$1sanitizeHtml(${part})`,
      ],
    ]);
    note =
      "sanitizeHtml comes from the 'sanitize-html' package (allowlist of tags); still encode on output.";
  }
  return after ? { before: s.trim(), after: after.trim(), note } : undefined;
}

export function contextualizeSecret({ finding }: ContextInput): ContextualExample | undefined {
  const s = finding.snippet;
  const env = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(s);
  if (env && !/['"`]/.test(s)) {
    return {
      before: s.trim(),
      after: `${env[1]}=  # set from your secret manager at deploy time; rotate the leaked value`,
      note: 'Remove the committed .env file from the repository (and its history), then rotate the credential.',
    };
  }
  const m = /([A-Za-z_$][\w$]*)\s*[:=]\s*(['"`])[^'"`]*\[redacted[^'"`]*\2/.exec(s);
  if (!m) return undefined;
  const name = m[1]!;
  const after = s.replace(/(['"`])[^'"`]*\[redacted[^'"`]*\1/, `process.env.${constCase(name)}`);
  return {
    before: s.trim(),
    after: after.trim(),
    note: /critical/.test(finding.severity)
      ? 'This file ships to the browser: move the call that needs the secret to the server instead of reading it client-side.'
      : `Provide ${constCase(name)} from the environment or a secret manager, and rotate the exposed value.`,
  };
}

export function contextualizeWeakCrypto({ finding }: ContextInput): ContextualExample | undefined {
  if (finding.cwe !== 'CWE-916') return undefined;
  if (finding.filePath.endsWith('.py')) {
    const py = rewrite(finding.snippet, [
      [
        /hashlib\.(?:md5|sha1|sha256)\(\s*(.+?)(?:\.encode\(\))?\s*\)\.hexdigest\(\)/,
        'PasswordHasher().hash($1)',
      ],
    ]);
    return py
      ? {
          before: finding.snippet.trim(),
          after: py.trim(),
          note: 'from argon2 import PasswordHasher (argon2-cffi); verify with PasswordHasher().verify(hash, password).',
        }
      : undefined;
  }
  if (!/\.(c|m)?[jt]sx?$/.test(finding.filePath)) return undefined;
  let after = rewrite(finding.snippet, [
    [
      /[\w.$]+\.createHash\(\s*['"][\w-]+['"]\s*\)\.update\(\s*([^)]+?)\s*\)\.digest\([^)]*\)/,
      'await argon2.hash($1)',
    ],
    [/\b(md5|sha1|sha256)\(\s*([^)]+?)\s*\)/, 'await argon2.hash($2)'],
  ]);
  // `await` needs an async function: fix one-line arrows like `const hash = (data) => …`.
  if (after && !/\basync\b/.test(after))
    after = after.replace(/(=\s*)(\([^)]*\)\s*=>)/, '$1async $2');
  return after
    ? {
        before: finding.snippet.trim(),
        after: after.trim(),
        note: 'Verify logins with argon2.verify(storedHash, password); the enclosing function must be async.',
      }
    : undefined;
}

export function contextualizeAccess({ finding }: ContextInput): ContextualExample | undefined {
  const s = finding.snippet;
  if (finding.cwe === 'CWE-639') {
    // One rewrite only: findByPk → owner-scoped findOne, else add the owner to `where`.
    const after =
      rewrite(s, [
        [/\.findByPk\(\s*([^,)]+?)\s*\)/, '.findOne({ where: { id: $1, UserId: req.user.id } })'],
      ]) ?? rewrite(s, [[/where:\s*\{\s*/, 'where: { UserId: req.user.id, ']]);
    return after
      ? {
          before: s.trim(),
          after: after.trim(),
          note: "Use your app's authenticated-user id (req.user / req.auth / session) and the model's owner column.",
        }
      : undefined;
  }
  const route = /(\b[\w$]+\.(?:get|post|put|patch|delete|all)\(\s*(['"`])[^'"`]+\2\s*,)/;
  if (route.test(s)) {
    return {
      before: s.trim(),
      after: s.replace(route, "$1 requireAuth, requireRole('admin'),").trim(),
      note: 'requireAuth / requireRole stand for your authentication and role-check middleware.',
    };
  }
  if (/^\s*[\w$]+\s*\(/.test(s)) {
    // Nest controller method
    return {
      before: s.trim(),
      after: `@UseGuards(AuthGuard('jwt'), RolesGuard)\n@Roles('admin')\n${s.trim()}`,
    };
  }
  return undefined;
}

export function contextualizeMassAssignment({
  finding,
}: ContextInput): ContextualExample | undefined {
  const s = finding.snippet;
  if (finding.cwe === 'CWE-213') {
    const after = rewrite(s, [
      [/(attributes|select|projection|fields)(\s*:\s*)([^}]+?)(\s*\})/, '$1$2SAFE_ATTRIBUTES$4'],
    ]);
    return after
      ? {
          before: s.trim(),
          after: `const SAFE_ATTRIBUTES = ['id', 'email', 'username']; // fixed, server-side list\n${after.trim()}`,
          note: 'List only columns the endpoint may expose; never password hashes or secrets.',
        }
      : undefined;
  }
  const privileged = /privileged field\(s\) ([^;]+?) that/.exec(finding.evidence[0] ?? '')?.[1];
  const after = rewrite(s, [[/\(\s*(req\.body|request\.body)\s*\)/, '(pick($1, ALLOWED_FIELDS))']]);
  if (!after) return undefined;
  return {
    before: s.trim(),
    after: `const ALLOWED_FIELDS = ['email', 'password']; // only what the client may set\n${after.trim()}`,
    note: privileged
      ? `Never include privileged fields (${privileged}); set them on the server.`
      : 'Adjust ALLOWED_FIELDS to the fields this endpoint should accept.',
  };
}

export function contextualizeCsrf({ finding }: ContextInput): ContextualExample | undefined {
  const s = finding.snippet;
  const route = /(\b[\w$]+\.(?:post|put|patch|delete|all)\(\s*(['"`])[^'"`]+\2\s*,)/;
  if (!route.test(s)) return undefined;
  return {
    before: s.trim(),
    after: s.replace(route, '$1 csrfProtection,').trim(),
    note: 'csrfProtection is e.g. doubleCsrfProtection from csrf-csrf; also set the cookie SameSite=Lax.',
  };
}

export function contextualizeDependency({ finding }: ContextInput): ContextualExample | undefined {
  const s = finding.snippet;
  const evidence = finding.evidence[0] ?? '';
  const intended = /likely intended package: (\S+)/.exec(evidence)?.[1];
  if (intended) {
    const after = rewrite(s, [
      [/"([^"]+)"(\s*:\s*)"[^"]*"/, `"${intended}"$2"<verify the current version>"`],
    ]);
    return after
      ? {
          before: s.trim(),
          after: after.trim(),
          note: `Confirm on the npm registry that "${intended}" is the package you meant before installing.`,
        }
      : undefined;
  }
  const fixed = /Fixed in ([^\s.]+(?:\.[^\s.]+)*)\./.exec(evidence)?.[1];
  const pkg = /^([^@\s]+|@[^@\s]+)@/.exec(evidence)?.[1];
  if (!fixed || !pkg) return undefined;
  if (/^\s*"[^"]+"\s*:\s*"[^"]*"/.test(s)) {
    return {
      before: s.trim(),
      after: s.replace(/(:\s*)"[^"]*"/, `$1"^${fixed}"`).trim(),
      note: 'Then run npm install and re-run the tests and the scan.',
    };
  }
  // Transitive (lockfile) entry: force the patched version with npm overrides.
  return {
    before: s.trim(),
    after: `// package.json\n"overrides": {\n  "${pkg}": "^${fixed}"\n}`,
    note: `${pkg} is transitive: prefer upgrading the direct dependency that pulls it in; overrides is the fallback.`,
  };
}

export function contextualizeMisconfig({ finding }: ContextInput): ContextualExample | undefined {
  const s = finding.snippet.trim();
  if (finding.cwe === 'CWE-693' && /=\s*express\(\s*\)/.test(s)) {
    const app = /(\w+)\s*=\s*express\(/.exec(s)?.[1] ?? 'app';
    return {
      before: s,
      after: `${s}\n${app}.use(helmet()); // CSP, HSTS, X-Content-Type-Options, ...`,
    };
  }
  if (/errorhandler\(\s*\)/.test(s)) {
    return { before: s, after: `if (process.env.NODE_ENV === 'development') {\n  ${s}\n}` };
  }
  if (/serveIndex\(/.test(s)) {
    return { before: s, after: '// directory listing removed: serve only explicit files' };
  }
  return undefined;
}

export function contextualizeExposure({ finding }: ContextInput): ContextualExample | undefined {
  const s = finding.snippet.trim();
  if (/\.jsonp\(/.test(s))
    return {
      before: s,
      after: s.replace(/\.jsonp\(/, '.json('),
      note: 'Allow cross-origin reads only for trusted origins via CORS.',
    };
  if (/serveIndex\(/.test(s))
    return { before: s, after: '// directory listing removed: serve only explicit files' };
  if (finding.lineStart === 1 && finding.filePath) {
    return {
      before: `// publicly served: ${finding.filePath}`,
      after: `// moved out of the served directory (e.g. to a private backup store) and removed from the deployment:\n// ${finding.filePath}`,
    };
  }
  return undefined;
}
