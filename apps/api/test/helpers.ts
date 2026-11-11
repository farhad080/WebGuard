import { signToken } from '../src/auth/jwt.js';
import { prisma } from '../src/db.js';

export async function resetDatabase(): Promise<void> {
  // Cascades to projects, scans, findings, and artifacts.
  await prisma.$executeRawUnsafe('TRUNCATE TABLE "users" CASCADE');
}

/** Creates a user directly in the DB and returns it with an Authorization header value. */
export async function createUserWithToken(email: string) {
  const user = await prisma.user.create({
    data: { email, passwordHash: 'not-a-real-hash' },
  });
  return { user, auth: `Bearer ${signToken({ id: user.id, email: user.email })}` };
}
