import type { Project, Scan } from '@prisma/client';
import { z } from 'zod';
import { prisma } from '../db.js';

const uuidSchema = z.string().uuid();

/** Returns the id if it is a valid UUID, otherwise null (callers respond 404). */
export function parseId(value: string | undefined): string | null {
  const parsed = uuidSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

/** Every project lookup is scoped to its owner; a project owned by someone else is "not found". */
export function findOwnedProject(userId: string, projectId: string): Promise<Project | null> {
  return prisma.project.findFirst({ where: { id: projectId, userId } });
}

/** Scans are owned through their project. */
export function findOwnedScan(userId: string, scanId: string): Promise<Scan | null> {
  return prisma.scan.findFirst({ where: { id: scanId, project: { userId } } });
}
