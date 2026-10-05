import { Router } from 'express';
import { exec } from 'node:child_process';

export const adminRouter = Router();

adminRouter.post('/backup', (req, res) => {
  const target = req.body.target as string;
  exec(`tar -czf /backups/${target}.tar.gz /data/${target}`, (err, stdout) => {
    if (err) return res.status(500).json({ error: 'backup failed' });
    res.json({ ok: true, stdout });
  });
});
