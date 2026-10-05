import { Router } from 'express';

export const redirectRouter = Router();

redirectRouter.get('/go', (req, res) => {
  const target = req.query.to as string;
  res.redirect(target);
});

redirectRouter.get('/go-safe', (req, res) => {
  const target = req.query.to as string;
  if (!target.startsWith('/') || target.startsWith('//') || target.includes('\\')) return res.status(400).end();
  res.redirect(target);
});
