import { Router } from 'express';
import path from 'node:path';
import fs from 'node:fs';

export const filesRouter = Router();

const UPLOAD_DIR = path.join(__dirname, '..', '..', 'uploads');

filesRouter.get('/download/:name', (req, res) => {
  res.sendFile(path.join(UPLOAD_DIR, req.params.name));
});

filesRouter.get('/read/:name', (req, res) => {
  const data = fs.readFileSync(path.join(UPLOAD_DIR, req.params.name));
  res.send(data);
});

filesRouter.get('/avatar/:name', (req, res) => {
  const safeName = path.basename(req.params.name);
  if (!/\.(png|jpg)$/.test(safeName)) return res.status(400).end();
  res.sendFile(path.join(UPLOAD_DIR, safeName));
});
