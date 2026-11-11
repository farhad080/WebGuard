import { builtinDetectors, DetectorRegistry } from '../registry.js';

// Built-in detectors. Each module registers itself on import via `registerDetector()`.
// To add a detector: create its module and add one import line here.
import './example-todo-comment.js';

/** A fresh registry with every built-in detector (callers may register more on it). */
export function createDefaultDetectorRegistry(): DetectorRegistry {
  return new DetectorRegistry(builtinDetectors.list());
}
