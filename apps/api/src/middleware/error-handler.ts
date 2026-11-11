import type { ErrorRequestHandler } from 'express';

/**
 * Final error middleware: logs server-side, returns a generic JSON body.
 * Never exposes stack traces or internal error messages to clients.
 */
export const errorHandler: ErrorRequestHandler = (err, _req, res, next) => {
  if (res.headersSent) {
    next(err);
    return;
  }

  const status =
    typeof err?.status === 'number' && err.status >= 400 && err.status < 500 ? err.status : 500;

  if (status >= 500) {
    console.error('[api] Unhandled error:', err);
  }

  res.status(status).json({ error: status === 500 ? 'Internal server error' : 'Bad request' });
};
