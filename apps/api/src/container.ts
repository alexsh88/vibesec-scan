import { AuditLogger } from './audit/AuditLogger';
import type { Config } from './config';
import { openDatabase, type Db } from './db/database';
import { EventRepo } from './db/eventRepo';
import { ScanRepo } from './db/scanRepo';
import { EventBus } from './events/EventBus';
import { JobRunner } from './jobs/JobRunner';
import { createStubPipeline } from './pipeline/stubPipeline';
import type { Pipeline } from './pipeline/types';
import { ScanLifecycle } from './scans/ScanLifecycle';
import { ScanService } from './scans/ScanService';

export type Container = {
  config: Config; db: Db; scans: ScanRepo; bus: EventBus; audit: AuditLogger;
  lifecycle: ScanLifecycle; runner: JobRunner; service: ScanService;
};

/** Composition root: the only place that wires concrete implementations together. */
export function createContainer(config: Config, overrides: { pipeline?: Pipeline } = {}): Container {
  const db = openDatabase(config.dbPath);
  const scans = new ScanRepo(db);
  const bus = new EventBus(new EventRepo(db));
  const audit = new AuditLogger(db);
  const lifecycle = new ScanLifecycle(scans, bus, db, audit);
  const runner = new JobRunner({
    scans, lifecycle, bus, audit,
    pipeline: overrides.pipeline ?? createStubPipeline(),
    config,
  });
  const service = new ScanService({ db, scans, lifecycle, audit, queue: runner, queueCapacity: config.queueCapacity });
  return { config, db, scans, bus, audit, lifecycle, runner, service };
}
