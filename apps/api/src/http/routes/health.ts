import type { FastifyInstance } from 'fastify';
import type { Container } from '../../container';

export function healthRoutes(app: FastifyInstance, c: Container): void {
  app.get('/api/health', async () => ({
    status: 'ok',
    scanMode: c.config.scanMode,
    docker: 'unknown', // probed by the sandbox module in P5
    queue: { pending: c.runner.pendingCount(), capacity: c.config.queueCapacity },
    git: c.gitVersion,
    llm: { mode: c.llm.mode, models: c.config.models }, // never include the API key
  }));
}
