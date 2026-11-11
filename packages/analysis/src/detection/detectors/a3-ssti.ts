import { findAll, matchesName, textOf } from '../../ast/queries.js';
import { traceTaint, type TaintTrace } from '../../ast/taint.js';
import type { AstNode } from '../../ast/types.js';
import { registerDetector } from '../registry.js';
import type { RawFinding } from '../types.js';
import { bestFlow, describeFlow, findingAt, parsedFiles, shorten } from './shared.js';

/**
 * A3 — Server-side template injection / dynamic code evaluation (dataflow).
 *
 * Objective: find user input that ends up executed as code: `eval`, `Function(...)`,
 * `vm.run*` / `vm.Script`, string `setTimeout`/`setInterval`, or a template engine compiling
 * a template *string* (`pug.compile`, `ejs.render`, `handlebars.compile`, `_.template`, ...).
 *
 * Sources: request input (`req.*`) and user-controlled profile fields read back from a
 * user object (`user.username`, `profile.bio`, ...), which is second-order input.
 *
 * Severity critical, because code execution on the server means full compromise.
 * Confidence: 0.95 for request input reaching the sink directly; 0.85 for a profile field;
 * 0.6 through an unknown call; 0.4 (low) for `eval`/`Function` over a dynamic value whose
 * origin can't be traced (still worth a look, since eval is rarely needed).
 *
 * False positives suppressed: evaluation of hard-coded constants (`eval('2+2')`), `vm`
 * sandboxes and template compilation whose input isn't user-influenced (e.g. a template read
 * from disk), and `setTimeout(fn)` with a function.
 */

const EVAL_SINKS = [
  'eval',
  'window.eval',
  'global.eval',
  'globalThis.eval',
  'Function',
  'setTimeout',
  'setInterval',
];
const SANDBOX_SINKS = [
  'vm.runInContext',
  'vm.runInNewContext',
  'vm.runInThisContext',
  'vm.Script',
  'vm.compileFunction',
];
/** Template engines: the *first* argument is the template source. */
const TEMPLATE_SINKS = [
  'pug.compile', 'pug.render', 'jade.compile', 'jade.render', 'ejs.compile', 'ejs.render',
  'handlebars.compile', 'Handlebars.compile', 'hbs.compile', '_.template', 'lodash.template',
  'nunjucks.renderString', 'doT.template', 'dot.template', 'swig.compile', 'swig.render',
  'Mustache.render', 'mustache.render', 'Vue.compile',
]; // prettier-ignore

const CATEGORY = 'A05:2025-Injection' as const;

const isSource = (n: AstNode) =>
  n.tags.includes('source:http-input') || n.tags.includes('source:user-profile');

function confidenceFor(trace: TaintTrace): number {
  const flow = bestFlow(trace);
  if (!flow) return 0;
  if (flow.throughCall) return 0.6;
  return flow.source.tags.includes('source:http-input') ? 0.95 : 0.85;
}

export const ssti = registerDetector({
  id: 'A3-ssti',
  title: 'Server-side template injection / code evaluation',
  owaspCategory: CATEGORY,
  technique: 'dataflow',
  explanation:
    'User-controlled text is evaluated as code on the server (eval, Function, vm, or a ' +
    'template engine compiling a template string). An attacker who controls that text, ' +
    'for example by setting their username to #{global.process.mainModule.require(' +
    "'child_process').execSync('id')}, runs arbitrary JavaScript with the server's " +
    'privileges, leading to full remote code execution.',
  fixSuggestion:
    'Remove eval/Function/vm on user data. Parse data (JSON.parse) instead of evaluating it, ' +
    'or map input to an allowlist of operations. Keep templates static and pass user ' +
    'values only as render data (auto-escaped), never as template source.',

  run(ctx) {
    const findings: RawFinding[] = [];
    for (const file of parsedFiles(ctx)) {
      for (const call of findAll(file, (n) => n.type === 'Call')) {
        const isEval = EVAL_SINKS.some((p) => matchesName(call.name, p));
        const isSandbox = SANDBOX_SINKS.some((p) => matchesName(call.name, p));
        const isTemplate = TEMPLATE_SINKS.some((p) => matchesName(call.name, p));
        if (!isEval && !isSandbox && !isTemplate) continue;

        const args = call.arguments ?? [];
        // Function(a, b, body): every argument is code. Others: the first argument.
        const codeArgs = call.name === 'Function' ? args : args.slice(0, 1);
        if (/^set(Timeout|Interval)$/.test(call.name ?? '') && codeArgs[0]?.type === 'Function') {
          continue;
        }

        let best: { arg: AstNode; trace: TaintTrace; confidence: number } | undefined;
        for (const arg of codeArgs) {
          if (arg.type === 'Function') continue;
          const trace = traceTaint(arg, { isSource });
          const confidence = trace.tainted
            ? confidenceFor(trace)
            : isEval && trace.dynamic
              ? 0.4
              : 0;
          if (confidence > (best?.confidence ?? 0)) best = { arg, trace, confidence };
        }
        if (!best) continue;

        const flow = bestFlow(best.trace);
        const sink = `${call.name}()`;
        findings.push(
          findingAt(ctx, file, call, {
            detectorId: 'A3-ssti',
            owaspCategory: CATEGORY,
            severity: best.trace.tainted ? 'critical' : 'high',
            confidence: best.confidence,
            evidence: flow
              ? `User-controlled ${describeFlow(file, best.arg, flow)} is evaluated as code by ${sink}`
              : `Dynamic value \`${shorten(textOf(file, best.arg), 80)}\` is evaluated by ${sink}; its origin could not be traced in this file`,
          }),
        );
      }
    }
    return findings;
  },
});
