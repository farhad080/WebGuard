import { createHash, randomBytes } from 'node:crypto';
import { Prisma } from '@prisma/client';
import { Router } from 'express';
import { prisma } from '../db.js';
import { asyncHandler } from '../middleware/async-handler.js';
import { signToken } from './jwt.js';
import { authMiddleware } from './middleware.js';
import { getDummyHash, hashPassword, verifyPassword } from './password.js';
import {
  forgotPasswordSchema,
  loginSchema,
  registerSchema,
  resetPasswordSchema,
} from './schemas.js';
import { getMailer } from './mailer.js';
import { config } from '../config.js';

export const authRouter = Router();

authRouter.post(
  '/register',
  asyncHandler(async (req, res) => {
    const parsed = registerSchema.safeParse(req.body);
    if (!parsed.success) {
      res
        .status(400)
        .json({ error: 'Invalid request', details: parsed.error.flatten().fieldErrors });
      return;
    }
    const { email, password } = parsed.data;

    try {
      const user = await prisma.user.create({
        data: { email, passwordHash: await hashPassword(password) },
        select: { id: true, email: true },
      });
      res.status(201).json(user);
    } catch (err) {
      if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002') {
        res.status(409).json({ error: 'Email already registered' });
        return;
      }
      throw err;
    }
  }),
);

authRouter.post(
  '/login',
  asyncHandler(async (req, res) => {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(401).json({ error: 'Invalid email or password' });
      return;
    }
    const { email, password } = parsed.data;

    const user = await prisma.user.findUnique({ where: { email } });
    const valid = await verifyPassword(user?.passwordHash ?? (await getDummyHash()), password);
    if (!user || !valid) {
      res.status(401).json({ error: 'Invalid email or password' });
      return;
    }

    res.status(200).json({ token: signToken({ id: user.id, email: user.email }) });
  }),
);

authRouter.get(
  '/me',
  authMiddleware,
  asyncHandler(async (req, res) => {
    const user = await prisma.user.findUnique({
      where: { id: req.user!.id },
      select: { id: true, email: true },
    });
    if (!user) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }
    res.status(200).json(user);
  }),
);

// ---------------------------------------------------------------------------
// Password reset
// ---------------------------------------------------------------------------

const RESET_TTL_MS = 30 * 60 * 1000;
const hashToken = (token: string) => createHash('sha256').update(token).digest('hex');
const GENERIC_RESET_MESSAGE =
  'If an account exists for that email, password reset instructions have been sent.';

/**
 * Always answers 202 with the same message, whether or not the account exists (no account
 * enumeration). Only a SHA-256 hash of the single-use token is stored; it expires in 30 min.
 */
authRouter.post(
  '/forgot-password',
  asyncHandler(async (req, res) => {
    const parsed = forgotPasswordSchema.safeParse(req.body);
    if (!parsed.success) {
      res
        .status(400)
        .json({ error: 'Invalid request', details: parsed.error.flatten().fieldErrors });
      return;
    }
    const user = await prisma.user.findUnique({ where: { email: parsed.data.email } });
    if (user) {
      const token = randomBytes(32).toString('base64url');
      await prisma.passwordResetToken.create({
        data: {
          userId: user.id,
          tokenHash: hashToken(token),
          expiresAt: new Date(Date.now() + RESET_TTL_MS),
        },
      });
      const url = `${config.appBaseUrl}/reset-password?token=${encodeURIComponent(token)}`;
      await getMailer()
        .sendPasswordReset(user.email, url)
        .catch((err) => console.error('[auth] could not send reset email', err));
    }
    res.status(202).json({ message: GENERIC_RESET_MESSAGE });
  }),
);

authRouter.post(
  '/reset-password',
  asyncHandler(async (req, res) => {
    const parsed = resetPasswordSchema.safeParse(req.body);
    if (!parsed.success) {
      res
        .status(400)
        .json({ error: 'Invalid request', details: parsed.error.flatten().fieldErrors });
      return;
    }
    const record = await prisma.passwordResetToken.findUnique({
      where: { tokenHash: hashToken(parsed.data.token) },
    });
    if (!record || record.usedAt || record.expiresAt.getTime() < Date.now()) {
      res.status(400).json({ error: 'This reset link is invalid or has expired' });
      return;
    }
    const passwordHash = await hashPassword(parsed.data.password);
    await prisma.$transaction([
      prisma.user.update({ where: { id: record.userId }, data: { passwordHash } }),
      prisma.passwordResetToken.update({ where: { id: record.id }, data: { usedAt: new Date() } }),
      // Any other outstanding links for this user stop working too.
      prisma.passwordResetToken.deleteMany({ where: { userId: record.userId, usedAt: null } }),
    ]);
    res.status(204).end();
  }),
);
