// Usage: node scripts/with-env.mjs <command> [args...]
// Loads the repo-root .env (if present) and runs the command with it.
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { config } from 'dotenv';

config({ path: fileURLToPath(new URL('../../../.env', import.meta.url)), quiet: true });

const [command, ...args] = process.argv.slice(2);
if (!command) {
  console.error('Usage: node scripts/with-env.mjs <command> [args...]');
  process.exit(1);
}

const child = spawn(command, args, { stdio: 'inherit', shell: true });
child.on('exit', (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  process.exit(code ?? 1);
});
