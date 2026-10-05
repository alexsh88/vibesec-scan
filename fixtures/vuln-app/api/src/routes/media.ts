import { Router } from 'express';
import { exec } from 'node:child_process';

export const mediaRouter = Router();

mediaRouter.post('/convert', (req, res) => {
  const filename = req.body.filename as string;
  exec(`convert /uploads/${filename} /uploads/${filename}.png`, (err) => {
    if (err) return res.status(500).json({ error: 'convert failed' });
    res.json({ ok: true });
  });
});
