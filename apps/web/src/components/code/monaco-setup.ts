import { loader } from '@monaco-editor/react';
import * as monaco from 'monaco-editor/esm/vs/editor/editor.api';
// Editor UI features (hover, find, folding, …) — no language services.
import 'monaco-editor/esm/vs/editor/editor.all.js';
// Lightweight Monarch syntax highlighting for every basic language (lazy-loaded per language).
import 'monaco-editor/esm/vs/basic-languages/monaco.contribution.js';
import EditorWorker from 'monaco-editor/esm/vs/editor/editor.worker?worker';

// The code view is read-only highlighting, so Monaco is loaded WITHOUT its language services
// (TypeScript/JSON/CSS/HTML workers): they are heavy and would each need their own worker —
// handing them the base editor worker makes Monaco try an AMD-only code path and throw
// "Cannot read properties of undefined (reading 'toUrl')". The base editor worker is all the
// remaining features need. Always the locally bundled Monaco, never the default CDN loader.
self.MonacoEnvironment = {
  getWorker: () => new EditorWorker(),
};

loader.config({ monaco: monaco as unknown as Parameters<typeof loader.config>[0]['monaco'] });

export { monaco };
