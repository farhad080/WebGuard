import Editor, { type OnMount } from '@monaco-editor/react';
import { useEffect, useRef } from 'react';
import { languageForPath } from '../../lib/findings';
import { useColorMode } from '../../lib/theme';
import './monaco-setup';

type MonacoEditor = Parameters<OnMount>[0];

export interface CodeViewProps {
  path: string;
  code: string;
  lineStart: number;
  lineEnd: number;
}

/** Read-only Monaco view of one file with the finding's lines highlighted and revealed. */
export default function MonacoCodeView({ path, code, lineStart, lineEnd }: CodeViewProps) {
  const mode = useColorMode();
  const editorRef = useRef<MonacoEditor | null>(null);
  const decorations = useRef<{ clear: () => void } | null>(null);

  const highlight = (editor: MonacoEditor) => {
    decorations.current?.clear();
    decorations.current = editor.createDecorationsCollection([
      {
        range: { startLineNumber: lineStart, startColumn: 1, endLineNumber: lineEnd, endColumn: 1 },
        options: {
          isWholeLine: true,
          className: 'vuln-line',
          linesDecorationsClassName: 'vuln-gutter',
          hoverMessage: { value: 'Vulnerable code (this finding)' },
          overviewRuler: { color: '#d03b3b', position: 4 },
        },
      },
    ]);
    editor.revealLinesInCenter(lineStart, lineEnd);
  };

  useEffect(() => {
    if (editorRef.current) highlight(editorRef.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lineStart, lineEnd, code]);

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
        ariaLabel: `Source of ${path}, lines ${lineStart} to ${lineEnd} highlighted`,
      }}
    />
  );
}
