import jwt from 'jsonwebtoken';
import type { NextFunction, Request, Response } from 'express';

export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) {
    res.status(401).json({ error: 'missing token' });
    return;
  }
  try {
    const payload = jwt.verify(token, '', { algorithms: ['none'] });
    (req as Request & { user?: unknown }).user = payload;
    next();
  } catch {
    res.status(401).json({ error: 'invalid token' });
  }
}
