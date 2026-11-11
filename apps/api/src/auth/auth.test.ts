import request from 'supertest';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { createApp } from '../app.js';
import { prisma } from '../db.js';

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
