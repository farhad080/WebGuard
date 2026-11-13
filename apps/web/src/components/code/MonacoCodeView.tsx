import Editor, { type OnMount } from '@monaco-editor/react';
import { useEffect, useRef } from 'react';
import { languageForPath } from '../../lib/findings';
import { useColorMode } from '../../lib/theme';
import { clampRange, type FileMark } from './scan-file';
import './monaco-setup';

type MonacoEditor = Parameters<OnMount>[0];

const NO_MARKS: readonly FileMark[] = [];

export interface CodeViewProps {
  path: string;
  code: string;
  /** The finding's lines to highlight and reveal; omit to only show the marks. */
  lineStart?: number;
  lineEnd?: number;
  /** Other findings in the same file: marked in the gutter and the overview ruler. */
  marks?: readonly FileMark[];
  /** Overrides the accessible name of the editor. */
  ariaLabel?: string;
}

/**
 * Read-only Monaco view of one file: the finding's lines are highlighted and scrolled into
 * view; other findings in the file get a gutter marker. Shared by the finding detail page and
 * the findings file viewer.
 */
export default function MonacoCodeView({
  path,
  code,
  lineStart,
  lineEnd,
  marks = NO_MARKS,
  ariaLabel,
}: CodeViewProps) {
  const mode = useColorMode();
  const editorRef = useRef<MonacoEditor | null>(null);
  const decorations = useRef<{ clear: () => void } | null>(null);

  const highlight = (editor: MonacoEditor) => {
    decorations.current?.clear();
    const lineCount = editor.getModel()?.getLineCount() ?? 0;
    const whole = (r: { lineStart: number; lineEnd: number }) => ({
      startLineNumber: r.lineStart,
      startColumn: 1,
      endLineNumber: r.lineEnd,
      endColumn: 1,
    });
    const others = marks.flatMap((m) => {
      const r = clampRange(m, lineCount);
      return r
        ? [
            {
              range: whole(r),
              options: {
                isWholeLine: true,
                className: 'other-finding-line',
                linesDecorationsClassName: `other-finding-gutter sev-${m.severity}`,
                hoverMessage: { value: `Other finding: ${m.label}` },
                overviewRuler: { color: '#c98500', position: 1 },
              },
            },
          ]
        : [];
    });
    const active =
      lineStart === undefined
        ? null
        : clampRange({ lineStart, lineEnd: lineEnd ?? lineStart }, lineCount);
    decorations.current = editor.createDecorationsCollection([
      ...others,
      ...(active
        ? [
            {
              range: whole(active),
              options: {
                isWholeLine: true,
                className: 'vuln-line',
                linesDecorationsClassName: 'vuln-gutter',
                hoverMessage: { value: 'Vulnerable code (this finding)' },
                overviewRuler: { color: '#d03b3b', position: 4 },
              },
            },
          ]
        : []),
    ]);
    if (active) editor.revealLinesInCenter(active.lineStart, active.lineEnd);
  };

  useEffect(() => {
    if (editorRef.current) highlight(editorRef.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lineStart, lineEnd, code, marks]);

  return (
    <Editor
      height="100%"
      path={path}
      value={code}
      language={languageForPath(path)}
      theme={mode === 'dark' ? 'vs-dark' : 'vs'}
      loading={<span className="muted">Loading editor…</span>}
      onMount={(editor) => {
        editorRef.current = editor;
        highlight(editor);
      }}
      options={{
        readOnly: true,
        domReadOnly: true,
        minimap: { enabled: false },
        scrollBeyondLastLine: false,
        renderLineHighlight: 'none',
        wordWrap: 'off',
        fontSize: 13,
        lineNumbersMinChars: 4,
        automaticLayout: true,
        contextmenu: false,
        ariaLabel:
          ariaLabel ??
          (lineStart === undefined
            ? `Source of ${path}`
            : `Source of ${path}, lines ${lineStart} to ${lineEnd ?? lineStart} highlighted`),
      }}
    />
  );
}
