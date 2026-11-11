import { registerDetector } from '../registry.js';
import type { RawFinding } from '../types.js';

/**
 * Reference detector (harmless example): flags `TODO SECURITY` comments so the whole
 * pipeline (registry → engine → de-dup → persistence → API) can be exercised end to end.
 * Copy this file as a template for new detectors.
 */

// A comment marker (`//`, `#`, `/*`, `*`, `<!--`, `--`) followed by "TODO SECURITY",
// "TODO(security)", "TODO: SECURITY", etc.
const TODO_SECURITY = /(?:\/\/|#|\/\*|^\s*\*|<!--|--)\s*TODO\b[\s:(\-[]*SECURITY\b/i;

export const exampleTodoComment = registerDetector({
  id: 'example-todo-comment',
  title: 'Security TODO left in code',
  owaspCategory: 'A06:2025-Insecure Design',
  cwe: 'CWE-546',
  technique: 'pattern',
  explanation:
    'A "TODO SECURITY" comment marks a known, unresolved security gap. It is a reminder, ' +
    'not a vulnerability by itself, but it often points at missing validation or controls.',
  fixSuggestion:
    'Resolve the security work described in the comment (or track it in your issue tracker) ' +
    'and remove the TODO.',

  run(ctx) {
    const findings: RawFinding[] = [];
    for (const file of ctx.sourceFiles) {
      const text = ctx.readText(file.path);
      if (text === null || !/TODO/i.test(text)) continue;
      const lines = text.split('\n');
      lines.forEach((line, i) => {
        if (!TODO_SECURITY.test(line)) return;
        findings.push({
          detectorId: 'example-todo-comment',
          owaspCategory: 'A06:2025-Insecure Design',
          severity: 'info',
          confidence: 1,
          filePath: file.path,
          lineStart: i + 1,
          lineEnd: i + 1,
          snippet: ctx.snippet(file.path, i + 1),
          evidence: `"TODO SECURITY" comment: ${line.trim().slice(0, 120)}`,
        });
      });
    }
    return findings;
  },
});
