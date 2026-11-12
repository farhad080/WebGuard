import { unlink } from 'node:fs/promises';
import type { Project } from '@prisma/client';
import type { ProjectWithLastScan, ScanSummary } from '@webguard/core';
import { Router } from 'express';
import { authMiddleware } from '../auth/middleware.js';
import { prisma } from '../db.js';
import { asyncHandler } from '../middleware/async-handler.js';
import { createQueuedScan } from '../scans/create-scan.js';
import { getStorage, storageKeys } from '../scans/storage.js';
import { zipUpload } from '../scans/upload.js';
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
      include: { scans: { orderBy: [{ createdAt: 'desc' }, { id: 'desc' }], take: 1 } },
    });
    const body: ProjectWithLastScan[] = projects.map(({ scans, ...project }) => {
      const last = scans[0];
      return {
        ...toProject(project),
        lastScan: last
          ? {
              id: last.id,
              status: last.status,
              createdAt: last.createdAt.toISOString(),
              finishedAt: last.finishedAt?.toISOString() ?? null,
              rollup: (last.summaryJson as ScanSummary | null)?.rollup ?? null,
            }
          : null,
      };
    });
    res.json(body);
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
    const owned = id ? await findOwnedProject(req.user!.id, id) : null;
    const scans = owned
      ? await prisma.scan.findMany({ where: { projectId: owned.id }, select: { id: true } })
      : [];
    const { count } = owned
      ? await prisma.project.deleteMany({ where: { id: owned.id, userId: req.user!.id } })
      : { count: 0 };
    if (count === 0) {
      res.status(404).json(notFound);
      return;
    }
    // Rows cascade in the database; the stored files (upload, extracted tree, reports) are
    // removed here so nothing of a deleted project stays on disk.
    const storage = getStorage();
    await Promise.all(
      scans.map((s) =>
        storage
          .deletePrefix(storageKeys.scanRoot(s.id))
          .catch((err) => console.error(`[projects] could not delete files of scan ${s.id}`, err)),
      ),
    );
    res.status(204).end();
  }),
);

projectsRouter.post(
  '/:id/scans',
  // Ownership is checked before the upload is read, so non-owners can't store anything.
  asyncHandler(async (req, res, next) => {
    const id = parseId(req.params.id);
    const project = id && (await findOwnedProject(req.user!.id, id));
    if (!project) {
      res.status(404).json(notFound);
      return;
    }
    res.locals.project = project;
    next();
  }),
  zipUpload(),
  asyncHandler(async (req, res) => {
    const project = res.locals.project as Project;
    const file = req.file!;
    try {
      const scan = await createQueuedScan(project.id, file.path);
      res.status(201).json(toScan(scan));
    } finally {
      await unlink(file.path).catch(() => undefined);
    }
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
