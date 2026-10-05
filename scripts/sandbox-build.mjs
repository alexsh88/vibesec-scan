#!/usr/bin/env node
// Builds the three sandbox images: <prefix>/sandbox-{node,python,proxy}:<TAG>.
// Usage: npm run sandbox:build   (SANDBOX_IMAGE_PREFIX overrides the "vibesec" prefix)
// Base images are pinned by tag + digest inside each Dockerfile; package-manager / typescript versions are ARGs there.
import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Must match SANDBOX_IMAGE_TAG in apps/api/src/sandbox/dockerSandbox.ts. */
const TAG = 'v1';
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const prefix = process.env.SANDBOX_IMAGE_PREFIX || 'vibesec';
if (!/^[a-z0-9][a-z0-9._/-]*$/.test(prefix)) {
  console.error(`invalid SANDBOX_IMAGE_PREFIX: ${prefix}`);
  process.exit(2);
}

const docker = (args, opts = {}) => spawnSync('docker', args, { stdio: 'inherit', shell: false, ...opts });

const version = spawnSync('docker', ['version', '--format', '{{.Server.Version}}'], { encoding: 'utf8', shell: false });
if (version.status !== 0) {
  console.error('Docker is not available (is Docker Desktop / dockerd running?)\n', version.stderr ?? '');
  process.exit(1);
}
console.log(`docker server ${version.stdout.trim()}`);

const images = ['proxy', 'python', 'node'];
for (const kind of images) {
  const ctx = join(ROOT, 'sandbox', kind);
  const name = `${prefix}/sandbox-${kind}:${TAG}`;
  console.log(`\n=== building ${name} (context ${ctx}) ===`);
  const r = docker(['build', '--label', 'org.opencontainers.image.source=vibesec-scan', '-t', name, '-f', join(ctx, 'Dockerfile'), ctx]);
  if (r.status !== 0) {
    console.error(`build failed: ${name}`);
    process.exit(r.status ?? 1);
  }
}

console.log('\nimages:');
for (const kind of images) {
  const name = `${prefix}/sandbox-${kind}:${TAG}`;
  const r = spawnSync('docker', ['image', 'inspect', '--format', '{{.Size}}', name], { encoding: 'utf8', shell: false });
  const mb = (Number(r.stdout.trim()) / 1024 / 1024).toFixed(1);
  console.log(`  ${name}  ${mb} MB`);
}
