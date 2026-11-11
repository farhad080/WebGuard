import { TECHNIQUE_STAGES, type Detector, type Technique } from './types.js';

const ID_PATTERN = /^[a-z0-9][a-z0-9-]*$/i;

export class DetectorRegistry {
  private readonly detectors = new Map<string, Detector>();

  constructor(detectors: Iterable<Detector> = []) {
    for (const d of detectors) this.register(d);
  }

  register(detector: Detector): this {
    if (!ID_PATTERN.test(detector.id)) {
      throw new Error(`Invalid detector id "${detector.id}" (use letters, digits, and dashes)`);
    }
    if (this.detectors.has(detector.id)) {
      throw new Error(`Detector "${detector.id}" is already registered`);
    }
    if (!(TECHNIQUE_STAGES as readonly string[]).includes(detector.technique)) {
      throw new Error(`Detector "${detector.id}" has unknown technique "${detector.technique}"`);
    }
    this.detectors.set(detector.id, detector);
    return this;
  }

  get(id: string): Detector | undefined {
    return this.detectors.get(id);
  }

  /** In registration order. */
  list(): Detector[] {
    return [...this.detectors.values()];
  }

  byTechnique(technique: Technique): Detector[] {
    return this.list().filter((d) => d.technique === technique);
  }

  get size(): number {
    return this.detectors.size;
  }
}

/**
 * Built-in detectors register themselves here at import time via {@link registerDetector}.
 * Adding a detector = a new module that calls `registerDetector(...)`, imported once from
 * `detectors/index.ts`. The engine never changes.
 */
export const builtinDetectors = new DetectorRegistry();

export function registerDetector<T extends Detector>(detector: T): T {
  builtinDetectors.register(detector);
  return detector;
}
