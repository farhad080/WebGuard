import { Prisma } from '@prisma/client';
import { Router } from 'express';
import { prisma } from '../db.js';
import { asyncHandler } from '../middleware/async-handler.js';
import { signToken } from './jwt.js';
import { authMiddleware } from './middleware.js';
import { getDummyHash, hashPassword, verifyPassword } from './password.js';
import { loginSchema, registerSchema } from './schemas.js';

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
