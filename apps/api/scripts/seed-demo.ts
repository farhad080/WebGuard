/**
 * Demo seed: a demo user, the "Acme Shop" vulnerable sample project, and a queued scan of it.
 *
 *   npm run seed:demo                 # from the repo root (loads .env)
 *   npm run seed:demo -- --no-scan    # user + project only
 *
 * Idempotent: re-running resets the demo user's password, reuses the project, and queues a new
 * scan (so the history/compare view fills up). The worker must be running to process the scan.
 * Also writes the sample ZIP to apps/api/demo/acme-shop.zip for manual uploads.
 */
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildDemoZip, DEMO_PROJECT_NAME } from '../demo/vulnerable-shop.js';
import { hashPassword } from '../src/auth/password.js';
import { prisma } from '../src/db.js';
import { createQueuedScan } from '../src/scans/create-scan.js';
import { closeScanQueue } from '../src/scans/queue.js';

const email = (process.env.DEMO_EMAIL ?? 'demo@webguard.local').toLowerCase();
const password = process.env.DEMO_PASSWORD ?? 'webguard-demo';
const queueScan = !process.argv.includes('--no-scan');
const zipOut = fileURLToPath(new URL('../demo/acme-shop.zip', import.meta.url));

async function main() {
  if (process.env.NODE_ENV === 'production' && !process.argv.includes('--force')) {
    throw new Error(
      'Refusing to seed a demo account with a known password in production (--force to override)',
    );
  }
  if (password.length < 8) throw new Error('DEMO_PASSWORD must be at least 8 characters');

  const passwordHash = await hashPassword(password);
  const user = await prisma.user.upsert({
    where: { email },
    update: { passwordHash },
    create: { email, passwordHash },
  });
  const project =
    (await prisma.project.findFirst({ where: { userId: user.id, name: DEMO_PROJECT_NAME } })) ??
    (await prisma.project.create({ data: { userId: user.id, name: DEMO_PROJECT_NAME } }));

  const zip = buildDemoZip();
  await writeFile(zipOut, zip);

  let scanId: string | undefined;
  if (queueScan) {
    const dir = await mkdtemp(path.join(os.tmpdir(), 'webguard-seed-'));
    try {
      const zipPath = path.join(dir, 'acme-shop.zip');
      await writeFile(zipPath, zip);
      scanId = (await createQueuedScan(project.id, zipPath)).id;
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }

  const app = (process.env.APP_BASE_URL ?? 'http://localhost:5173').replace(/\/+$/, '');
  console.log(
    [
      '',
      'WebGuard demo seeded',
      `  user      ${email}`,
      `  password  ${password}`,
      `  project   ${DEMO_PROJECT_NAME} (${project.id})`,
      scanId
        ? `  scan      ${scanId} (queued — start the worker to process it)`
        : '  scan      (skipped)',
      `  zip       ${path.relative(process.cwd(), zipOut)} (for manual upload)`,
      '',
      `Open ${app}/login${scanId ? ` — then ${app}/scans/${scanId}` : ''}`,
      '',
    ].join('\n'),
  );
}

main()
  .catch((err) => {
    console.error(`[seed] ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
  })
  .finally(async () => {
    await closeScanQueue().catch(() => undefined);
    await prisma.$disconnect();
  });
