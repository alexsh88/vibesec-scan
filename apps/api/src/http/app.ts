import { randomUUID } from 'node:crypto';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import Fastify, { type FastifyInstance, type FastifyServerOptions } from 'fastify';
import type { Container } from '../container';
import { errorHandler } from './errorHandler';
import { serializeError } from './logSerializers';
import { auditRoutes } from './routes/audit';
import { diagnosticsRoutes } from './routes/diagnostics';
import { eventRoutes } from './routes/events';
import { findingRoutes } from './routes/findings';
import { healthRoutes } from './routes/health';
import { indexRoutes } from './routes/index';
import { scanRoutes } from './routes/scans';

export async function buildApp(c: Container, opts: { logger?: FastifyServerOptions['logger'] } = {}): Promise<FastifyInstance> {
  const app = Fastify({
    logger: opts.logger ?? {
      level: 'info',
      redact: { paths: ['req.headers.authorization', 'req.body.auth.token', '*.token'], censor: '[REDACTED]' },
      serializers: { err: serializeError },
    },
    genReqId: () => randomUUID(),
    requestIdHeader: 'x-request-id',
  });

  await app.register(cors, { origin: c.config.corsOrigin });
  await app.register(rateLimit, { max: 300, timeWindow: '1 minute' });
  app.setErrorHandler(errorHandler);

  scanRoutes(app, c.service);
  indexRoutes(app, c.service, c.indexRepo);
  findingRoutes(app, c);
  diagnosticsRoutes(app, c);
  eventRoutes(app, c.service, c.bus);
  auditRoutes(app, c.audit);
  healthRoutes(app, c);

  return app;
}
