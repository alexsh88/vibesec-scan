import type { FastifyError, FastifyReply, FastifyRequest } from 'fastify';
import { ZodError } from 'zod';
import { AppError } from '../errors/AppError';

export function errorHandler(err: FastifyError | Error, req: FastifyRequest, reply: FastifyReply) {
  const requestId = req.id;

  if (err instanceof ZodError) {
    return reply.code(400).send({
      error: {
        code: 'VALIDATION', message: 'Invalid request', requestId,
        issues: err.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
      },
    });
  }

  if (err instanceof AppError) {
    if (err.retryAfterMs) reply.header('retry-after', Math.ceil(err.retryAfterMs / 1000));
    if (err.httpStatus >= 500) req.log.error({ err, code: err.code }, 'request failed');
    return reply.code(err.httpStatus).send({ error: { code: err.code, message: err.userMessage, requestId } });
  }

  const status = 'statusCode' in err && typeof err.statusCode === 'number' ? err.statusCode : 500;
  if (status === 429) {
    return reply.code(429).send({ error: { code: 'RATE_LIMITED', message: 'Too many requests', requestId } });
  }
  if (status >= 400 && status < 500) {
    return reply.code(status).send({ error: { code: 'VALIDATION', message: err.message, requestId } });
  }

  req.log.error({ err }, 'unhandled error');
  return reply.code(500).send({ error: { code: 'INTERNAL', message: 'Unexpected internal error', requestId } });
}
