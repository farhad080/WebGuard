import { Router } from 'express';
import { authMiddleware } from '../auth/middleware.js';
import { prisma } from '../db.js';
import { asyncHandler } from '../middleware/async-handler.js';
import { findOwnedProject, parseId } from './ownership.js';
import { projectBodySchema } from './schemas.js';
import { toProject, toScan } from './serializers.js';

export const projectsRouter = Router();
projectsRouter.use(authMiddleware);

const notFound = { error: 'Not found' } as const;

projectsRouter.post(
  '/',
  asyncHandler(async (req, res) => {
    const parsed = projectBodySchema.safeParse(req.body);
    if (!parsed.success) {
      res
        .status(400)
        .json({ error: 'Invalid request', details: parsed.error.flatten().fieldErrors });
      return;
    }
    const project = await prisma.project.create({
      data: { name: parsed.data.name, userId: req.user!.id },
    });
    res.status(201).json(toProject(project));
  }),
);

projectsRouter.get(
  '/',
  asyncHandler(async (req, res) => {
    const projects = await prisma.project.findMany({
      where: { userId: req.user!.id },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
    });
    res.json(projects.map(toProject));
  }),
);

projectsRouter.get(
  '/:id',
  asyncHandler(async (req, res) => {
    const id = parseId(req.params.id);
    const project = id && (await findOwnedProject(req.user!.id, id));
    if (!project) {
      res.status(404).json(notFound);
      return;
    }
    res.json(toProject(project));
  }),
);

projectsRouter.patch(
  '/:id',
  asyncHandler(async (req, res) => {
    const id = parseId(req.params.id);
    if (!id) {
      res.status(404).json(notFound);
      return;
    }
    const parsed = projectBodySchema.safeParse(req.body);
    if (!parsed.success) {
      res
        .status(400)
        .json({ error: 'Invalid request', details: parsed.error.flatten().fieldErrors });
      return;
    }
    // Ownership is part of the WHERE clause, so another user's project is never touched.
    const { count } = await prisma.project.updateMany({
      where: { id, userId: req.user!.id },
      data: { name: parsed.data.name },
    });
    const project = count > 0 ? await findOwnedProject(req.user!.id, id) : null;
    if (!project) {
      res.status(404).json(notFound);
      return;
    }
    res.json(toProject(project));
  }),
);

projectsRouter.delete(
  '/:id',
  asyncHandler(async (req, res) => {
    const id = parseId(req.params.id);
    const { count } = id
      ? await prisma.project.deleteMany({ where: { id, userId: req.user!.id } })
      : { count: 0 };
    if (count === 0) {
      res.status(404).json(notFound);
      return;
    }
    res.status(204).end();
  }),
);

projectsRouter.post(
  '/:id/scans',
  asyncHandler(async (req, res) => {
    const id = parseId(req.params.id);
    const project = id && (await findOwnedProject(req.user!.id, id));
    if (!project) {
      res.status(404).json(notFound);
      return;
    }
    const scan = await prisma.scan.create({ data: { projectId: project.id } });
    res.status(201).json(toScan(scan));
  }),
);

projectsRouter.get(
  '/:id/scans',
  asyncHandler(async (req, res) => {
    const id = parseId(req.params.id);
    const project = id && (await findOwnedProject(req.user!.id, id));
    if (!project) {
      res.status(404).json(notFound);
      return;
    }
    const scans = await prisma.scan.findMany({
      where: { projectId: project.id },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
    });
    res.json(scans.map(toScan));
  }),
);
