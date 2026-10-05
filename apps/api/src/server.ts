import { loadConfig, loadDotEnv } from './config';
import { createContainer } from './container';
import { buildApp } from './http/app';

const SHUTDOWN_GRACE_MS = 20_000;

async function main(): Promise<void> {
  loadDotEnv();
  const config = loadConfig();
  const c = createContainer(config);
  const app = await buildApp(c);

  try {
    c.gitVersion = await c.git.init();
  } catch (err) {
    app.log.fatal({ err }, 'git is required but could not be run');
    process.exit(1);
  }

  // Listen first: if the port is taken (e.g. a second instance), we exit here before touching any scan,
  // instead of adopting / failing the other instance's work.
  await app.listen({ port: config.port, host: config.host });

  const { resumed, failed } = c.runner.recover();
  if (resumed.length || failed.length) app.log.info({ resumed, failed }, 'recovered scans from previous run');

  // Sweep after recover(): scans it just failed are terminal now, so their checkouts are removed too.
  const live = new Set(c.scans.listNonTerminal().map((s) => s.id));
  const removed = await c.git.sweep((scanId) => live.has(scanId));
  if (removed.length) app.log.info({ removed: removed.length }, 'removed stale scan workspaces');
  // Best-effort: leftover sandbox containers/networks/volumes/staging dirs from a previous run.
  if (c.sandbox) await c.sandbox.sweep().catch((err: unknown) => app.log.warn({ err }, 'sandbox sweep failed'));
  c.runner.startWatchdog();
  app.log.info({ scanMode: config.scanMode }, 'vibesec api ready');

  let shuttingDown = false;
  const shutdown = async (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    app.log.info({ signal }, 'shutting down: draining scans');
    await c.runner.shutdown(SHUTDOWN_GRACE_MS); // new scans now get 503; running scans checkpoint
    await app.close(); // preClose sends `reconnect` to open SSE streams
    c.db.close();
    process.exit(0);
  };
  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
