import express, { type Express } from 'express';
import helmet from 'helmet';
import { authRouter } from './auth/routes.js';
import { projectsRouter } from './domain/projects.routes.js';
import { scansRouter } from './domain/scans.routes.js';
import { errorHandler } from './middleware/error-handler.js';

export function createApp(): Express {
  const app = express();
  app.disable('x-powered-by');
  app.use(helmet());
  app.use(express.json({ limit: '100kb' }));

  app.get('/api/health', (_req, res) => {
    res.status(200).json({ status: 'ok' });
  });

  app.use('/api/auth', authRouter);
  app.use('/api/projects', projectsRouter);
  app.use('/api/scans', scansRouter);

  app.use((_req, res) => {
    res.status(404).json({ error: 'Not found' });
  });

  app.use(errorHandler);

  return app;
}
