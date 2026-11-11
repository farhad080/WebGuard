import { findAll, matchesName, textOf, walk } from '../../ast/queries.js';
import {
  interpolatedParts,
  isStringBuilding,
  resolveValues,
  stringParts,
  traceTaint,
  type TaintFlow,
  type TaintTrace,
} from '../../ast/taint.js';
import type { AstNode, ParsedFile } from '../../ast/types.js';
import { registerDetector } from '../registry.js';
import type { DetectionContext, RawFinding } from '../types.js';
import { bestFlow, describeFlow, findingAt, parsedFiles, shorten } from './shared.js';

/**
 * A4 — Cross-site scripting (dataflow + AST), classified as DOM, reflected, or stored.
 *
 * Sinks:
 *  - DOM/HTML writes: `el.innerHTML =` / `outerHTML =`, `document.write[ln]()`,
 *    `insertAdjacentHTML()`, jQuery `$(…).html()`.
 *  - Framework trust bypasses: Angular `bypassSecurityTrustHtml/Script/Url/ResourceUrl/Style`,
 *    React `dangerouslySetInnerHTML={{ __html }}`. Auto-escaping bindings (`{{ value }}`,
 *    Angular `[innerHTML]` without a bypass, which Angular sanitizes, and React `{value}`) are
 *    safe by default and never flagged. A `[innerHTML]` binding is only cited as the render
 *    location of a value that went through a bypass.
 *  - Server reflection: `res.send/write/end()` of a string built from request input
 *    (Express sends strings as text/html).
 *  - Stored: a model field that renders as HTML (description, email, comment, ...) written
 *    from request input via `create/update/insert…` or `instance.field = …`.
 *
 * Classification:
 *  - dom: browser code writes URL-controlled data (location, Angular route params) to an HTML sink.
 *  - reflected: request input echoed in a server HTML response, or URL data that round-trips
 *    through a service call (`.subscribe(res => …)`) before reaching an HTML sink.
 *  - stored: request input saved to a renderable model field, or a renderable model field /
 *    profile value (`user.email`, `product.description`) reaching an HTML sink.
 *
 * Severity high. Confidence: 0.85 when taint is proven directly; 0.6 through an unknown call;
 * 0.8 for a stored write whose field is rendered unsafely elsewhere in the project (0.4 when
 * no unsafe render site was found, as auto-escaped output may make it harmless); 0.5 (medium)
 * for an HTML sink with a plausible but unproven source.
 *
 * Sanitisers recognized: DOMPurify.sanitize, sanitize-html, xss/filterXSS, escape-html, he,
 * lodash/validator escape, Angular `sanitizer.sanitize()`, encodeURIComponent.
 *
 * Juice Shop coverage:
 *  - #26 / #27 DOM XSS: search query param → `bypassSecurityTrustHtml` → `[innerHTML]`
 *    (and the equivalent direct `innerHTML =` write).
 *  - #28 Reflected XSS: track-order `id` param → order API response → `bypassSecurityTrustHtml`.
 *  - #29 API-only XSS (stored): product description written via the API, rendered with
 *    `bypassSecurityTrustHtml(product.description)`.
 *  - #30 Client-side XSS protection (stored): email validated only in the browser, stored via
 *    the API, rendered in the admin user list through `bypassSecurityTrustHtml(user.email)`.
 *
 * Limitations: intra-procedural (plus class fields and callback params); client↔server links
 * are made by field name, not by following HTTP calls; Vue `v-html` / Svelte `{@html}` /
 * EJS `<%- %>` / Pug `!{}` / Handlebars `{{{ }}}` are used only as render-site evidence.
 */

const CATEGORY = 'A05:2025-Injection' as const;
type XssClass = 'dom' | 'reflected' | 'stored';

const XSS_SANITIZERS = [
  'DOMPurify.sanitize',
  'purify.sanitize',
  '*.sanitize',
  'sanitize',
  'sanitizeHtml',
  'xss',
  'filterXSS',
  '*.filterXSS',
  'escape',
  'escapeHtml',
  '*.escape',
  '*.escapeHtml',
  'he.encode',
  'he.escape',
  'encodeURIComponent',
  'encodeURI',
  'xssFilters.inHTMLData',
  'entities.encodeHTML',
];

/** Model fields that are typically rendered back into pages. */
const RENDERABLE_FIELDS = new Set([
  'description', 'comment', 'comments', 'message', 'bio', 'about', 'name', 'title', 'email',
  'username', 'content', 'text', 'review', 'address', 'note', 'notes', 'summary', 'caption',
  'html', 'label', 'displayName', 'firstName', 'lastName', 'fullName', 'subject', 'feedback',
  'body', 'signature', 'status', 'nickname',
]); // prettier-ignore

const STORE_METHODS = new Set([
  'create', 'bulkCreate', 'build', 'update', 'upsert', 'insert', 'insertOne', 'insertMany',
  'updateOne', 'updateMany', 'findOneAndUpdate', 'replaceOne', 'save', 'set',
]); // prettier-ignore

const SELECTOR_FIRST = new Set([
  'update',
  'updateOne',
  'updateMany',
  'findOneAndUpdate',
  'replaceOne',
]);

const BYPASS = /^bypassSecurityTrust(Html|Script|Url|ResourceUrl|Style)$/;
const RESPONSE_ROOTS = new Set(['res', 'response', 'reply']);
const WHOLE_REQUEST_OBJECT = /^(req|request)\.(body|query|params|headers|cookies)$/;

const EXPLANATIONS: Record<XssClass, string> = {
  dom:
    'DOM-based XSS: browser code takes attacker-controlled URL data (query string, fragment, ' +
    'route parameter) and writes it into the page as HTML. An attacker sends a victim a link ' +
    'such as /#/search?q=<iframe src="javascript:alert(document.cookie)"> and the payload ' +
    "runs in the victim's session, able to steal tokens, act as the user, or rewrite the page.",
  reflected:
    'Reflected XSS: input from the request is echoed back and rendered as HTML without ' +
    'encoding. An attacker crafts a link (e.g. ?id=<script>…</script>) that, when a victim ' +
    "opens it, makes the application itself deliver the attacker's script into the victim's " +
    "browser, where it runs with the victim's cookies and privileges.",
  stored:
    'Stored XSS: user-supplied text (e.g. a product description or an email address) is ' +
    'saved without sanitisation and later rendered as HTML for other users. The payload ' +
    'persists and runs for everyone who views the page, often administrators, which ' +
    'makes it ideal for account takeover. Client-side validation does not help: attackers ' +
    'call the API directly.',
};

const FIXES: Record<XssClass, string> = {
  dom:
    'Write untrusted values with textContent / default Angular or React bindings instead of ' +
    'innerHTML, never call bypassSecurityTrust* or dangerouslySetInnerHTML on user input, and ' +
    'sanitise with DOMPurify.sanitize() when HTML is genuinely needed.',
  reflected:
    'Encode output for its HTML context (e.g. escape-html) or return JSON via res.json() ' +
    'instead of building HTML from request input; add a Content-Security-Policy.',
  stored:
    'Sanitise rich text on input (sanitize-html / DOMPurify) and encode on output; render ' +
    'stored values with auto-escaping bindings, not innerHTML, bypassSecurityTrust*, or ' +
    'dangerouslySetInnerHTML.',
};

const LABEL: Record<XssClass, string> = {
  dom: 'DOM XSS',
  reflected: 'Reflected XSS',
  stored: 'Stored XSS',
};

const anySource = (n: AstNode) =>
  n.tags.includes('source:http-input') ||
  n.tags.includes('source:client-url') ||
  n.tags.includes('source:user-profile');
const httpSource = (n: AstNode) => n.tags.includes('source:http-input');

function renderableFields(expr: AstNode): string[] {
  const out = new Set<string>();
  for (const n of walk(expr)) {
    if (n.type === 'MemberAccess' && n.property && RENDERABLE_FIELDS.has(n.property)) {
      out.add(n.property);
    }
  }
  return [...out];
}

function propertyKey(prop: AstNode): string | undefined {
  const key = (prop.raw as { key?: { type: string; name?: string; value?: string } }).key;
  return key?.type === 'Identifier' ? key.name : key?.value;
}

/** Identifier at the root of `res.status(200).send` → `res`. */
function responseRoot(callee: AstNode): string | undefined {
  let node: AstNode | undefined = callee.object;
  while (node) {
    if (node.type === 'Identifier') return node.name;
    if (node.type === 'Call') node = node.callee?.object ?? node.callee;
    else if (node.type === 'MemberAccess') node = node.object;
    else return undefined;
  }
  return undefined;
}

function unwrapAwait(node: AstNode): AstNode {
  let n = node;
  while (n.rawType === 'AwaitExpression' && n.children[0]) n = n.children[0];
  return n;
}

function isModelish(receiver: AstNode | undefined, depth = 0): boolean {
  if (!receiver) return false;
  const name = receiver.name ?? '';
  const last = name.split('.').at(-1) ?? '';
  if (
    /^[A-Z][A-Za-z0-9]*$/.test(last) ||
    /model|collection|repo(sitory)?$/i.test(last) ||
    /^(db|this\.db)\./.test(name)
  ) {
    return true;
  }
  // `const product = await ProductModel.findByPk(id); product.update({...})`
  if (receiver.type === 'Identifier' && depth < 2) {
    return resolveValues(receiver).some((v) => {
      const value = unwrapAwait(v);
      return (
        value !== receiver &&
        value.type === 'Call' &&
        value.callee?.type === 'MemberAccess' &&
        isModelish(value.callee.object, depth + 1)
      );
    });
  }
  return false;
}

function htmlInLiterals(expr: AstNode): boolean {
  return stringParts(expr).some(
    (p) =>
      (p.type === 'StringLiteral' && /<\/?[a-z]/i.test(p.value ?? '')) ||
      (p.type === 'TemplateLiteral' &&
        p.children.some(
          (c) =>
            c.rawType === 'TemplateElement' &&
            /<\/?[a-z]/i.test((c.raw as { value: { raw: string } }).value.raw),
        )),
  );
}

// ---------------------------------------------------------------------------
// Template render sites (Angular/Vue/Svelte/EJS/Pug/Handlebars)
// ---------------------------------------------------------------------------

interface TemplateBinding {
  path: string;
  line: number;
  kind: string;
  expr: string;
  words: Set<string>;
  /** Unescaped by the framework (Vue v-html, EJS <%-, ...). Angular [innerHTML] is sanitized. */
  unsafe: boolean;
}

const TEMPLATE_PATTERNS: Array<{ kind: string; re: RegExp; unsafe: boolean }> = [
  { kind: '[innerHTML]', re: /\[innerHTML\]\s*=\s*"([^"]*)"/g, unsafe: false },
  { kind: 'v-html', re: /v-html\s*=\s*"([^"]*)"/g, unsafe: true },
  { kind: '{@html}', re: /\{@html\s+([^}]*)\}/g, unsafe: true },
  { kind: '<%- %>', re: /<%-\s*([\s\S]*?)%>/g, unsafe: true },
  { kind: '!{}', re: /!\{([^}]*)\}/g, unsafe: true },
  { kind: '{{{ }}}', re: /\{\{\{\s*([^}]*?)\s*\}\}\}/g, unsafe: true },
];

function scanTemplates(ctx: DetectionContext): TemplateBinding[] {
  const out: TemplateBinding[] = [];
  for (const file of ctx.sourceFiles) {
    if (!/\.(html?|vue|svelte|ejs|pug|jade|hbs|handlebars)$/i.test(file.path)) continue;
    const text = ctx.readText(file.path);
    if (!text) continue;
    for (const { kind, re, unsafe } of TEMPLATE_PATTERNS) {
      for (const m of text.matchAll(re)) {
        const expr = m[1] ?? '';
        out.push({
          path: file.path,
          line: text.slice(0, m.index).split('\n').length,
          kind,
          expr: expr.trim(),
          words: new Set(expr.match(/[A-Za-z_$][\w$]*/g) ?? []),
          unsafe,
        });
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Detector
// ---------------------------------------------------------------------------

interface ClientSink {
  file: ParsedFile;
  at: AstNode;
  value: AstNode;
  sink: string;
}

interface StoredWrite {
  file: ParsedFile;
  at: AstNode;
  field: string; // '*' = the whole request object (mass assignment)
  value: AstNode;
  trace: TaintTrace;
  via: string;
}

function clientSinks(file: ParsedFile): ClientSink[] {
  const out: ClientSink[] = [];
  for (const n of walk(file)) {
    if (
      n.type === 'Assignment' &&
      n.left?.type === 'MemberAccess' &&
      (n.left.property === 'innerHTML' || n.left.property === 'outerHTML') &&
      n.right
    ) {
      out.push({ file, at: n, value: n.right, sink: `.${n.left.property} =` });
    } else if (n.type === 'Call') {
      const callee = n.callee;
      const method = callee?.type === 'MemberAccess' ? callee.property : undefined;
      const args = n.arguments ?? [];
      if (
        ['document.write', 'document.writeln', '*.document.write'].some((p) =>
          matchesName(n.name, p),
        )
      ) {
        if (args[0]) out.push({ file, at: n, value: args[0], sink: `${n.name}()` });
      } else if (method === 'insertAdjacentHTML' && args[1]) {
        out.push({ file, at: n, value: args[1], sink: 'insertAdjacentHTML()' });
      } else if (method && BYPASS.test(method) && args[0]) {
        out.push({ file, at: n, value: args[0], sink: `${method}()` });
      } else if (
        method === 'html' &&
        callee?.object?.type === 'Call' &&
        ['$', 'jQuery'].includes(callee.object.name ?? '') &&
        args[0]
      ) {
        out.push({ file, at: n, value: args[0], sink: '$(…).html()' });
      }
    } else if (n.rawType === 'JSXAttribute') {
      const attrName = (n.raw as { name?: { name?: string } }).name?.name;
      if (attrName !== 'dangerouslySetInnerHTML') continue;
      for (const inner of walk(n)) {
        if (inner.type === 'Property' && propertyKey(inner) === '__html') {
          const value = inner.children.at(-1);
          if (value) out.push({ file, at: n, value, sink: 'dangerouslySetInnerHTML' });
        }
      }
    }
  }
  return out;
}

function storedWrites(file: ParsedFile): StoredWrite[] {
  const out: StoredWrite[] = [];
  const consider = (at: AstNode, field: string, value: AstNode, via: string) => {
    const trace = traceTaint(value, { isSource: httpSource, sanitizers: XSS_SANITIZERS });
    if (trace.tainted) out.push({ file, at, field, value, trace, via });
  };
  const fromObject = (at: AstNode, obj: AstNode, via: string) => {
    for (const prop of obj.children) {
      if (prop.type !== 'Property') continue;
      const key = propertyKey(prop);
      const value = prop.children.at(-1);
      if (!key || !value) continue;
      if (key.startsWith('$') && value.type === 'Object')
        fromObject(at, value, via); // $set
      else if (RENDERABLE_FIELDS.has(key)) consider(at, key, value, via);
    }
  };

  for (const n of walk(file)) {
    if (n.type === 'Call' && n.callee?.type === 'MemberAccess') {
      const method = n.callee.property ?? '';
      if (!STORE_METHODS.has(method) || !isModelish(n.callee.object)) continue;
      const via = `${n.name}()`;
      // Mongo-style update(selector, doc): the selector picks documents, only `doc` is written.
      const args = n.arguments ?? [];
      const written = SELECTOR_FIRST.has(method) && args.length >= 2 ? args.slice(1, 2) : args;
      for (const arg of written) {
        for (const value of resolveValues(arg)) {
          if (value.type === 'Object') {
            fromObject(n, value, via);
          } else {
            // `Model.create(req.body)`: every field comes from the client.
            const trace = traceTaint(value, { isSource: httpSource, sanitizers: XSS_SANITIZERS });
            if (
              trace.tainted &&
              trace.flows.some((f) => WHOLE_REQUEST_OBJECT.test(f.source.name ?? ''))
            ) {
              out.push({ file, at: n, field: '*', value, trace, via });
            }
          }
        }
      }
    } else if (
      n.type === 'Assignment' &&
      n.left?.type === 'MemberAccess' &&
      n.right &&
      n.left.property &&
      RENDERABLE_FIELDS.has(n.left.property) &&
      n.left.object?.rawType !== 'ThisExpression' &&
      isModelish(n.left.object)
    ) {
      consider(n, n.left.property, n.right, `${n.left.name} =`);
    }
  }
  return out;
}

function confidenceForFlow(flow: TaintFlow): number {
  return flow.throughCall ? 0.6 : 0.85;
}

export const xss = registerDetector({
  id: 'A4-xss',
  title: 'Cross-site scripting (XSS)',
  owaspCategory: CATEGORY,
  cwe: 'CWE-79',
  technique: 'dataflow',
  explanation: EXPLANATIONS.dom,
  fixSuggestion: FIXES.dom,

  run(ctx) {
    const files = parsedFiles(ctx);
    const templates = scanTemplates(ctx);
    const writes = files.flatMap(storedWrites);
    const sinks = files.flatMap(clientSinks);
    const findings: RawFinding[] = [];

    const emit = (
      file: ParsedFile,
      at: AstNode,
      cls: XssClass,
      confidence: number,
      evidence: string,
    ) => {
      findings.push(
        findingAt(ctx, file, at, {
          detectorId: 'A4-xss',
          owaspCategory: CATEGORY,
          severity: 'high',
          confidence,
          evidence: `${LABEL[cls]}: ${evidence}`,
          explanation: EXPLANATIONS[cls],
          fixSuggestion: FIXES[cls],
        }),
      );
    };

    // Fields that are rendered unsafely somewhere (client sinks or unescaped templates).
    const renderSites = new Map<string, string>();
    const noteRender = (field: string, where: string) => {
      if (!renderSites.has(field)) renderSites.set(field, where);
    };

    // ---- Client-side HTML sinks ----
    const analysed = sinks.map((s) => {
      const trace = traceTaint(s.value, { isSource: anySource, sanitizers: XSS_SANITIZERS });
      const fields = trace.tainted || trace.dynamic ? renderableFields(s.value) : [];
      for (const f of trace.flows) {
        if (f.source.tags.includes('source:user-profile') && f.source.property)
          fields.push(f.source.property);
      }
      for (const field of fields)
        noteRender(field, `${s.file.path}:${s.at.loc.startLine} (${s.sink})`);
      return { ...s, trace, fields };
    });
    for (const t of templates) {
      if (!t.unsafe) continue;
      for (const w of t.words)
        if (RENDERABLE_FIELDS.has(w)) noteRender(w, `${t.path}:${t.line} (${t.kind})`);
    }
    const writtenFields = new Set(writes.map((w) => w.field));
    const writtenSomewhere = (fields: string[]) =>
      writtenFields.has('*') ? fields.length > 0 : fields.some((f) => writtenFields.has(f));

    for (const s of analysed) {
      const { file, at, value, sink, trace, fields } = s;
      const flow = bestFlow(trace);

      // Where the bypassed value is rendered (Angular `[innerHTML]="field"`).
      let renderedAt = '';
      if (
        BYPASS.test(sink.replace('()', '')) &&
        at.parent?.type === 'Assignment' &&
        at.parent.left?.property
      ) {
        const target = at.parent.left.property;
        const binding = templates.find((t) => t.kind === '[innerHTML]' && t.words.has(target));
        if (binding)
          renderedAt = `; rendered via [innerHTML]="${binding.expr}" at ${binding.path}:${binding.line}`;
      }

      if (flow) {
        const tag = flow.source.tags;
        let cls: XssClass;
        let confidence = confidenceForFlow(flow);
        if (tag.includes('source:client-url')) cls = flow.throughCallback ? 'reflected' : 'dom';
        else if (tag.includes('source:http-input')) cls = 'reflected';
        else {
          cls = 'stored';
          confidence = writtenSomewhere(fields) ? 0.8 : 0.7;
        }
        const origin =
          cls === 'reflected' && flow.throughCallback
            ? ' (round-trips through a service response)'
            : '';
        // Point at the tainted piece of a template/concatenation, not the whole string.
        const part = isStringBuilding(value)
          ? (interpolatedParts(value).find(
              (p) => traceTaint(p, { isSource: anySource, sanitizers: XSS_SANITIZERS }).tainted,
            ) ?? value)
          : value;
        emit(
          file,
          at,
          cls,
          confidence,
          `${describeFlow(file, part, flow)}${origin} reaches ${sink}${renderedAt}`,
        );
      } else if (trace.dynamic) {
        const text = `\`${shorten(textOf(file, value), 80)}\``;
        if (fields.length > 0) {
          const confirmed = writtenSomewhere(fields);
          emit(
            file,
            at,
            'stored',
            confirmed ? 0.7 : 0.5,
            `model field(s) ${fields.join(', ')} in ${text} reach ${sink}${renderedAt}${confirmed ? '; the same field is written from request input without sanitisation' : ''}`,
          );
        } else {
          emit(
            file,
            at,
            'dom',
            0.5,
            `dynamic value ${text} reaches ${sink}${renderedAt}; its origin could not be traced in this file`,
          );
        }
      }
    }

    // ---- Server reflection: res.send/write/end ----
    for (const file of files) {
      for (const call of findAll(file, (n) => n.type === 'Call')) {
        const callee = call.callee;
        const method = callee?.type === 'MemberAccess' ? callee.property : undefined;
        if (!callee || !method || !['send', 'write', 'end'].includes(method)) continue;
        if (!RESPONSE_ROOTS.has(responseRoot(callee) ?? '')) continue;
        const arg = call.arguments?.[0];
        if (!arg || arg.type === 'Object' || arg.type === 'Array') continue;

        const trace = traceTaint(arg, { isSource: httpSource, sanitizers: XSS_SANITIZERS });
        const flow = bestFlow(trace);
        if (!flow) continue;
        const building = isStringBuilding(arg);
        const html = building && htmlInLiterals(arg);
        // res.send(req.body) sends JSON; only strings are rendered as HTML.
        if (!building && WHOLE_REQUEST_OBJECT.test(flow.source.name ?? '')) continue;
        // res.send(render(locals)): the input only reaches the response through a function
        // (usually a compiled, auto-escaping template). Not reflected by itself.
        if (!building && !trace.direct) continue;
        // write()/end() have no default HTML content type; require visible markup.
        if (method !== 'send' && !html) continue;

        const part = building
          ? (interpolatedParts(arg).find((p) => traceTaint(p, { isSource: httpSource }).tainted) ??
            arg)
          : arg;
        const confidence = flow.throughCall ? 0.6 : html ? 0.85 : 0.8;
        emit(
          file,
          call,
          'reflected',
          confidence,
          `request input ${describeFlow(file, part, flow)} is echoed into the HTML response by ${responseRoot(callee)}.${method}()`,
        );
      }
    }

    // ---- Stored writes ----
    for (const w of writes) {
      const flow = bestFlow(w.trace)!;
      const site = w.field === '*' ? [...renderSites.values()][0] : renderSites.get(w.field);
      const field = w.field === '*' ? 'all fields (mass assignment)' : `the "${w.field}" field`;
      emit(
        w.file,
        w.at,
        'stored',
        site ? (flow.throughCall ? 0.6 : 0.8) : 0.4,
        `request input ${describeFlow(w.file, w.value, flow)} is saved to ${field} via ${w.via} without sanitisation` +
          (site
            ? `; it is rendered as HTML at ${site}`
            : '; no unsafe render site was found in this project, so it is only exploitable if another client renders it as HTML'),
      );
    }

    return findings;
  },
});
