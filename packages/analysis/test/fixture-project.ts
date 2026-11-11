import { cp, mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const MINI_EXPRESS = fileURLToPath(new URL('./fixtures/mini-express', import.meta.url));

/**
 * Copies the committed mini-express fixture to a temp dir and adds the files that can't be
 * committed (they match .gitignore): node_modules, dist, .git, .env, plus a binary and an
 * oversized file. Returns the temp project root.
 */
export async function materializeMiniExpress(): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), 'webguard-fixture-'));
  await cp(MINI_EXPRESS, root, { recursive: true });

  const put = async (rel: string, data: string | Buffer) => {
    const file = path.join(root, ...rel.split('/'));
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, data);
  };
  await put('node_modules/express/package.json', '{"name":"express"}');
  await put('node_modules/express/index.js', 'module.exports = function express() {};');
  await put('dist/bundle.js', 'console.log("built");');
  await put('.git/HEAD', 'ref: refs/heads/main\n');
  await put('.env', 'DATABASE_URL=postgres://user:secret@db/app\n');
  await put('LICENSE', 'MIT License\n');
  await put(
    'public/logo.png',
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0]),
  );
  await put('src/vendor.min.js', `var a=${'1+'.repeat(3000)}1;`);
  return root;
}
