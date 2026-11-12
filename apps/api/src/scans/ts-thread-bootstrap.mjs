// Development/test-only entry for worker threads whose real entry is TypeScript.
//
// Passing `--import tsx` in a Worker's execArgv is not honored by every Node version (Node 20
// ignores it), so instead the TypeScript loader is registered from inside the thread, then the
// real entry (workerData.__tsEntry) is imported. Production runs the compiled .js entry
// directly and never loads this file.
import { workerData } from 'node:worker_threads';
import { register } from 'tsx/esm/api';

register();
await import(workerData.__tsEntry);
