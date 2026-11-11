import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

/** Applies all migrations to the dedicated test database before the suite runs. */
export default function setup(): void {
  const url =
    process.env.TEST_DATABASE_URL ?? 'postgres://webguard:webguard@localhost:5432/webguard_test';
  const dbName = new URL(url).pathname.slice(1);
  if (!dbName.endsWith('_test')) {
    throw new Error(
      `Refusing to run tests (which truncate tables) against non-test database "${dbName}" (name must end in _test)`,
    );
  }

  // Non-destructive: applies pending migrations (creating the DB if needed).
  // Each test truncates its tables, so runs stay repeatable.
  execSync('npx prisma migrate deploy', {
    cwd: fileURLToPath(new URL('..', import.meta.url)),
    env: { ...process.env, DATABASE_URL: url },
    stdio: 'inherit',
  });
}
