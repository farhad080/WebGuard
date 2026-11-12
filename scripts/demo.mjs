#!/usr/bin/env node
// One-command demo: services → migrations → seed → API + worker + web.
//
//   npm run demo            # everything; Ctrl+C stops the app processes
//   npm run demo -- --setup # only services, migrations and seed (start the apps yourself)
//
// Requires Docker (Postgres + Redis via docker compose) and Node 20+.
import { spawn, spawnSync } from 'node:child_process';
import { copyFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const setupOnly = process.argv.includes('--setup');
const isWin = process.platform === 'win32';

function step(title, cmd, args) {
  console.log(`\n▶ ${title}`);
  const r = spawnSync(cmd, args, { cwd: root, stdio: 'inherit', shell: true });
  if (r.status !== 0) {
    console.error(`\n✖ ${title} failed (exit ${r.status}).`);
    process.exit(r.status ?? 1);
  }
}

if (!existsSync(`${root}/.env`)) {
  copyFileSync(`${root}/.env.example`, `${root}/.env`);
  console.log(
    'Created .env from .env.example (fine for a local demo; set a real JWT_SECRET otherwise).',
  );
}

step('Starting Postgres + Redis', 'docker', ['compose', 'up', '-d', '--wait']);
step('Applying database migrations', 'npm', ['run', 'db:migrate']);
step('Building shared packages', 'npm', ['run', 'build:packages']);
step('Seeding the demo user, project and scan', 'npm', ['run', 'seed:demo']);

if (setupOnly) {
  console.log('\nSetup done. Start the apps with: npm run dev · npm run worker · npm run dev:web');
  process.exit(0);
}

const procs = [
  ['api', ['run', 'dev', '--workspace', 'apps/api']],
  ['worker', ['run', 'worker']],
  ['web', ['run', 'dev', '--workspace', 'apps/web']],
].map(([name, args]) => {
  const child = spawn('npm', args, { cwd: root, shell: true, stdio: ['ignore', 'pipe', 'pipe'] });
  const prefix = (chunk) =>
    chunk
      .toString()
      .split(/\r?\n/)
      .filter(Boolean)
      .map((l) => `[${name}] ${l}`)
      .join('\n');
  child.stdout.on('data', (c) => console.log(prefix(c)));
  child.stderr.on('data', (c) => console.error(prefix(c)));
  child.on('exit', (code) => {
    if (!stopping) {
      console.error(`[${name}] exited (${code}); stopping the demo.`);
      stop(1);
    }
  });
  return child;
});

let stopping = false;
function stop(code = 0) {
  if (stopping) return;
  stopping = true;
  for (const p of procs) {
    if (p.exitCode !== null) continue;
    if (isWin) spawnSync('taskkill', ['/pid', String(p.pid), '/T', '/F'], { stdio: 'ignore' });
    else p.kill('SIGTERM');
  }
  setTimeout(() => process.exit(code), 500);
}
process.on('SIGINT', () => stop(0));
process.on('SIGTERM', () => stop(0));

console.log(
  '\n▶ Starting API, worker and web app — open http://localhost:5173 and sign in with the demo' +
    ' credentials printed above. The seeded scan runs as soon as the worker is up. Ctrl+C to stop.\n',
);
