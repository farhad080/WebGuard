// Regenerates the committed fixture archives: npx tsx test/fixtures/generate.ts
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { buildZip } from '../zip-writer.js';

const out = (name: string) => fileURLToPath(new URL(name, import.meta.url));

// A tiny, well-formed website project.
writeFileSync(
  out('valid-site.zip'),
  buildZip([
    {
      name: 'index.html',
      data: '<!doctype html><title>Demo</title><script src="app.js"></script>\n',
    },
    { name: 'src/', unixMode: 0o040755 },
    { name: 'src/app.js', data: 'document.title = "hello";\n', deflate: true },
    { name: 'src/lib/util.js', data: 'export const add = (a, b) => a + b;\n', deflate: true },
  ]),
);

// Classic zip-slip: an entry that tries to climb out of the extraction directory.
writeFileSync(
  out('zip-slip.zip'),
  buildZip([
    { name: 'readme.txt', data: 'looks harmless\n' },
    { name: '../../webguard-zip-slip-pwned.txt', data: 'escaped!\n' },
  ]),
);

console.log('fixtures written');
