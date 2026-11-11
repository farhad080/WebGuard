import type { Severity } from '@webguard/core';
import { z } from 'zod';

export const SEVERITIES = [
  'critical',
  'high',
  'medium',
  'low',
  'info',
] as const satisfies readonly Severity[];

export const projectBodySchema = z.object({
  name: z.string().trim().min(1).max(200),
});

/** `severity` accepts a single value or a comma-separated list, e.g. `?severity=critical,high`. */
export const findingsQuerySchema = z.object({
  severity: z
    .string()
    .transform((value) => value.split(',').map((s) => s.trim()))
    .pipe(z.array(z.enum(SEVERITIES)).min(1))
    .optional(),
  owaspCategory: z.string().trim().min(1).max(200).optional(),
  minConfidence: z.coerce.number().min(0).max(1).optional(),
});
