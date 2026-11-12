import cors from 'cors';
import express, { type Express } from 'express';
import { rateLimit } from 'express-rate-limit';
import helmet from 'helmet';
import { authMiddleware } from './auth/middleware.js';
import { authRouter } from './auth/routes.js';
import { config } from './config.js';
import { findingsRouter } from './domain/findings.routes.js';
import { projectsRouter } from './domain/projects.routes.js';
import { scansRouter } from './domain/scans.routes.js';
import { errorHandler } from './middleware/error-handler.js';
import { reportsRouter } from './reports/report.routes.js';

export interface AppOptions {
  /** Override the configured limits (tests). */
  rateLimits?: { auth?: number; upload?: number };
  /** Override the configured CORS origins (tests). */
  corsOrigins?: string[];
}

const tooMany = (message: string) => ({ error: message });

export function createApp(options: AppOptions = {}): Express {
  const app = express();
  app.disable('x-powered-by');
  // Behind a reverse proxy, client IPs (for rate limiting) come from X-Forwarded-For.
  if (config.trustProxy) app.set('trust proxy', config.trustProxy);
  app.use(helmet());

  // CORS: only the configured frontend origin(s). The SPA normally calls the API same-origin
  // (via the Vite proxy / a reverse proxy); this governs any cross-origin browser access.
  const origins = options.corsOrigins ?? config.corsOrigins;
  app.use(
    cors({
      origin: (origin, callback) => callback(null, !origin || origins.includes(origin)),
      methods: ['GET', 'POST', 'PATCH', 'DELETE'],
      allowedHeaders: ['Authorization', 'Content-Type'],
      exposedHeaders: ['Content-Disposition', 'Retry-After'],
      maxAge: 600,
    }),
  );

  app.use(express.json({ limit: '100kb' }));

  app.get('/api/health', (_req, res) => {
    res.status(200).json({ status: 'ok' });
  });

  // Brute-force / abuse protection: credential-handling auth endpoints, per client IP.
  const authLimiter = rateLimit({
    windowMs: 15 * 60_000,
    limit: options.rateLimits?.auth ?? config.authRateLimit,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    skip: (req) => req.method === 'GET',
    message: tooMany('Too many attempts. Wait a few minutes and try again.'),
  });
  // Uploads are expensive (storage + a scan job): per authenticated user, per hour.
  const uploadLimiter = rateLimit({
    windowMs: 60 * 60_000,
    limit: options.rateLimits?.upload ?? config.uploadRateLimit,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    keyGenerator: (req) => `user:${req.user!.id}`,
    message: tooMany('Upload limit reached. Try again later.'),
  });

  app.use('/api/auth', authLimiter, authRouter);
  app.post('/api/projects/:id/scans', authMiddleware, uploadLimiter);
  app.use('/api/projects', projectsRouter);
  app.use('/api/scans', scansRouter);
  app.use('/api/scans', reportsRouter);
  app.use('/api/findings', findingsRouter);

  // Nothing else is served: in particular the storage directory (uploads, extracted code,
  // reports) is never exposed statically — files are only reachable through the
  // ownership-checked API routes above.
  app.use((_req, res) => {
    res.status(404).json({ error: 'Not found' });
  });

  app.use(errorHandler);

  return app;
}
