import { builtinDetectors, DetectorRegistry } from '../registry.js';

// Built-in detectors. Each module registers itself on import via `registerDetector()`.
// To add a detector: create its module and add one import line here.
import './example-todo-comment.js';
import './a1-sql-injection.js';
import './a2-nosql-injection.js';
import './a3-ssti.js';
import './a4-xss.js';
import './a5-hardcoded-secrets.js';
import './a6-weak-crypto.js';
import './a8-access-control.js';
import './a9-mass-assignment.js';
import './a10-missing-csrf.js';
import './a7-sensitive-file-exposure.js';
import './a11-vulnerable-deps.js';
import './a12-security-misconfig.js';

/** A fresh registry with every built-in detector (callers may register more on it). */
export function createDefaultDetectorRegistry(): DetectorRegistry {
  return new DetectorRegistry(builtinDetectors.list());
}
