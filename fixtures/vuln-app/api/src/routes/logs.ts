import { Router } from 'express';
import fs from 'node:fs';

export const logsRouter = Router();

const LOG_DIR = '/var/log/vuln-app';

logsRouter.get('/', (req, res) => {
  const name = req.query.name as string;
  const content = fs.readFileSync(LOG_DIR + '/' + name, 'utf8');
  res.type('text/plain').send(content);
});
