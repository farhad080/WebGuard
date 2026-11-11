import jwt from 'jsonwebtoken';
import { config } from '../config.js';
import type { AuthUser } from '../types/express.js';

export function signToken(user: AuthUser): string {
  return jwt.sign({ sub: user.id, email: user.email }, config.jwtSecret, {
    algorithm: 'HS256',
    expiresIn: config.jwtExpiresIn,
  });
}

export function verifyToken(token: string): AuthUser {
  const payload = jwt.verify(token, config.jwtSecret, { algorithms: ['HS256'] });
  if (
    typeof payload !== 'object' ||
    typeof payload.sub !== 'string' ||
    typeof payload.email !== 'string'
  ) {
    throw new Error('Invalid token payload');
  }
  return { id: payload.sub, email: payload.email };
}
