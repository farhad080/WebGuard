import { describe, expect, it } from 'vitest';
import { ignoredDirOf } from './ignored-dirs.js';

const dirs = new Set(['node_modules', 'dist', '.git']);

describe('ignoredDirOf', () => {
  it('returns the top-most ignored directory of a path', () => {
    expect(ignoredDirOf('node_modules/a/b.js', dirs)).toBe('node_modules');
    expect(ignoredDirOf('a/node_modules/b/node_modules/c.js', dirs)).toBe('a/node_modules');
    expect(ignoredDirOf('web/dist/', dirs)).toBe('web/dist');
    expect(ignoredDirOf('.git/HEAD', dirs)).toBe('.git');
  });

  it('only matches whole directory segments, never the file name', () => {
    expect(ignoredDirOf('src/app.js', dirs)).toBeNull();
    expect(ignoredDirOf('dist', dirs)).toBeNull(); // a file named "dist"
    expect(ignoredDirOf('src/distance/x.js', dirs)).toBeNull();
    expect(ignoredDirOf('my_node_modules/x.js', dirs)).toBeNull();
    expect(ignoredDirOf('package.json', dirs)).toBeNull();
  });
});
