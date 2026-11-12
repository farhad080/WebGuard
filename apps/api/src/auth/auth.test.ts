import request from 'supertest';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { createApp } from '../app.js';
import { prisma } from '../db.js';
import { ConsoleMailer, setMailer } from './mailer.js';

const app = createApp();
const credentials = { email: 'alice@example.com', password: 'correct-horse-battery' };

beforeEach(async () => {
  await prisma.$executeRawUnsafe('TRUNCATE TABLE "users" CASCADE');
});

afterAll(async () => {
  await prisma.$disconnect();
});

async function register(body = credentials) {
  return request(app).post('/api/auth/register').send(body);
}

async function login(body = credentials) {
  return request(app).post('/api/auth/login').send(body);
}

describe('POST /api/auth/register', () => {
  it('creates a user and returns 201 with id and email only', async () => {
    const res = await register();
    expect(res.status).toBe(201);
    expect(res.body).toEqual({ id: expect.any(String), email: credentials.email });

    const stored = await prisma.user.findUniqueOrThrow({ where: { email: credentials.email } });
    expect(stored.passwordHash).not.toBe(credentials.password);
    expect(stored.passwordHash.startsWith('$argon2id$')).toBe(true);
  });

  it('rejects a duplicate email with 409', async () => {
    await register();
    const res = await register();
    expect(res.status).toBe(409);
  });

  it('rejects invalid input with 400', async () => {
    const res = await register({ email: 'not-an-email', password: 'short' });
    expect(res.status).toBe(400);
  });
});

describe('POST /api/auth/login', () => {
  it('returns 200 with a JWT for valid credentials', async () => {
    await register();
    const res = await login();
    expect(res.status).toBe(200);
    expect(res.body.token).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/);
  });

  it('returns 401 with a generic message for a wrong password', async () => {
    await register();
    const res = await login({ ...credentials, password: 'wrong-password' });
    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'Invalid email or password' });
  });

  it('returns the same 401 for an unknown email', async () => {
    const res = await login({ email: 'nobody@example.com', password: 'whatever123' });
    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'Invalid email or password' });
  });
});

describe('GET /api/auth/me', () => {
  it('returns the current user for a valid token', async () => {
    const { body: user } = await register();
    const { body } = await login();
    const res = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${body.token}`);
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ id: user.id, email: credentials.email });
  });

  it('returns 401 when the token is missing', async () => {
    const res = await request(app).get('/api/auth/me');
    expect(res.status).toBe(401);
  });

  it('returns 401 for an invalid token', async () => {
    const res = await request(app).get('/api/auth/me').set('Authorization', 'Bearer not.a.jwt');
    expect(res.status).toBe(401);
  });
});

describe('password reset', () => {
  let sent: { to: string; url: string }[];

  beforeEach(() => {
    sent = [];
    setMailer({
      sendPasswordReset: async (to, url) => {
        sent.push({ to, url });
      },
    });
  });

  afterAll(() => setMailer(new ConsoleMailer()));

  const forgot = (email: string) => request(app).post('/api/auth/forgot-password').send({ email });
  const reset = (token: string, password: string) =>
    request(app).post('/api/auth/reset-password').send({ token, password });
  const tokenOf = (url: string) => new URL(url).searchParams.get('token')!;

  it('answers the same 202 for known and unknown emails, mailing only real accounts', async () => {
    await register();
    const known = await forgot(credentials.email);
    const unknown = await forgot('nobody@example.com');
    expect(known.status).toBe(202);
    expect(unknown.status).toBe(202);
    expect(unknown.body).toEqual(known.body);
    expect(sent).toHaveLength(1);
    expect(sent[0]!.to).toBe(credentials.email);
    expect(sent[0]!.url).toMatch(/\/reset-password\?token=/);

    const stored = await prisma.passwordResetToken.findFirstOrThrow();
    expect(stored.tokenHash).not.toBe(tokenOf(sent[0]!.url));
  });

  it('resets the password once; the link then stops working', async () => {
    await register();
    await forgot(credentials.email);
    const token = tokenOf(sent[0]!.url);

    expect((await reset(token, 'brand-new-password')).status).toBe(204);
    expect((await login()).status).toBe(401);
    expect((await login({ ...credentials, password: 'brand-new-password' })).status).toBe(200);

    const again = await reset(token, 'another-password');
    expect(again.status).toBe(400);
    expect(again.body.error).toMatch(/invalid or has expired/);
  });

  it('invalidates other outstanding links after a reset', async () => {
    await register();
    await forgot(credentials.email);
    await forgot(credentials.email);
    expect((await reset(tokenOf(sent[1]!.url), 'brand-new-password')).status).toBe(204);
    expect((await reset(tokenOf(sent[0]!.url), 'other-password1')).status).toBe(400);
  });

  it('rejects expired and unknown tokens with 400', async () => {
    await register();
    await forgot(credentials.email);
    await prisma.passwordResetToken.updateMany({
      data: { expiresAt: new Date(Date.now() - 1000) },
    });
    expect((await reset(tokenOf(sent[0]!.url), 'brand-new-password')).status).toBe(400);
    expect((await reset('x'.repeat(43), 'brand-new-password')).status).toBe(400);
  });

  it('validates the new password length', async () => {
    await register();
    await forgot(credentials.email);
    expect((await reset(tokenOf(sent[0]!.url), 'short')).status).toBe(400);
  });
});
