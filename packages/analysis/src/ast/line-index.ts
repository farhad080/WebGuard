import type { SourceLocation } from './types.js';

/** Maps between character offsets and 1-based line / 0-based column positions. */
export class LineIndex {
  private readonly lineStarts: number[];

  constructor(private readonly text: string) {
    this.lineStarts = [0];
    for (let i = 0; i < text.length; i++) {
      if (text.charCodeAt(i) === 10 /* \n */) this.lineStarts.push(i + 1);
    }
  }

  get lineCount(): number {
    return this.lineStarts.length;
  }

  /** Offset of a 1-based line and 0-based column. */
  offsetOf(line: number, column: number): number {
    const start = this.lineStarts[Math.min(Math.max(line, 1), this.lineCount) - 1]!;
    return Math.min(start + column, this.text.length);
  }

  /** 1-based line / 0-based column for an offset. */
  positionOf(offset: number): { line: number; column: number } {
    let lo = 0;
    let hi = this.lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (this.lineStarts[mid]! <= offset) lo = mid;
      else hi = mid - 1;
    }
    return { line: lo + 1, column: offset - this.lineStarts[lo]! };
  }

  /** Text of a 1-based line, without its line terminator. */
  lineText(line: number): string {
    if (line < 1 || line > this.lineCount) return '';
    const start = this.lineStarts[line - 1]!;
    const end = line < this.lineCount ? this.lineStarts[line]! - 1 : this.text.length;
    return this.text.slice(start, end).replace(/\r$/, '');
  }

  /** Exact source text covered by a location. */
  slice(loc: SourceLocation): string {
    return this.text.slice(
      this.offsetOf(loc.startLine, loc.startCol),
      this.offsetOf(loc.endLine, loc.endCol),
    );
  }
}
