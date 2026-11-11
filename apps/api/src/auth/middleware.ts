import type { RequestHandler } from 'express';
import { verifyToken } from './jwt.js';

export const authMiddleware: RequestHandler = (req, res, next) => {
  const header = req.headers.authorization;
  const match = header?.match(/^Bearer\s+(\S+)$/i);
  if (!match?.[1]) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }
  try {
    req.user = verifyToken(match[1]);
    next();
  } catch {
    res.status(401).json({ error: 'Unauthorized' });
  }
};
