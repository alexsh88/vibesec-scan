import { describe, expect, it } from 'vitest';
import { detectEntrypoints, packageJsonBins } from '../src/index/entrypoints';

describe('detectEntrypoints (JS/TS)', () => {
  it('detects Next.js app-router route handlers with their methods', () => {
    const src = 'export async function GET(req) {}\nexport const POST = async () => {};\nfunction helper() {}';
    expect(detectEntrypoints('apps/web/app/api/users/[id]/route.ts', src)).toEqual([
      { path: 'apps/web/app/api/users/[id]/route.ts', kind: 'next-route', line: null, detail: 'GET,POST' },
    ]);
  });

  it('detects pages/api routes and server actions', () => {
    expect(detectEntrypoints('src/pages/api/login.ts', 'export default function handler() {}')[0]?.kind).toBe('next-api');
    expect(detectEntrypoints('app/actions.ts', "// actions\n'use server';\nexport async function save() {}")[0]?.kind).toBe('server-action');
    expect(detectEntrypoints('app/page.tsx', "'use client';\nexport default function P() {}")).toEqual([]);
  });

  it('detects Express/Fastify-style routes per line', () => {
    const src = [
      "const app = express();",
      "app.get('/users/:id', handler);",
      "router.post(\"/login\", login);",
      "fastify.delete(`/items/:id`, remove);",
      "map.get('key');",
    ].join('\n');
    expect(detectEntrypoints('src/server.js', src)).toEqual([
      { path: 'src/server.js', kind: 'http-route', line: 2, detail: 'GET /users/:id' },
      { path: 'src/server.js', kind: 'http-route', line: 3, detail: 'POST /login' },
      { path: 'src/server.js', kind: 'http-route', line: 4, detail: 'DELETE /items/:id' },
    ]);
  });

  it('detects routes on named Express routers/apps (invoicesRouter, adminApp)', () => {
    const src = [
      "export const invoicesRouter = Router();",
      "invoicesRouter.get('/:id', async (req, res) => {});",
      "adminApp.post('/backup', run);",
      "settings.get('/x');",
    ].join('\n');
    expect(detectEntrypoints('src/routes/invoices.ts', src)).toEqual([
      { path: 'src/routes/invoices.ts', kind: 'http-route', line: 2, detail: 'GET /:id' },
      { path: 'src/routes/invoices.ts', kind: 'http-route', line: 3, detail: 'POST /backup' },
    ]);
  });

  it('detects serverless handlers and Supabase edge functions', () => {
    expect(detectEntrypoints('lambda/index.ts', 'export const handler = async (event) => {}')[0])
      .toMatchObject({ kind: 'serverless', line: 1 });
    expect(detectEntrypoints('fn.js', 'exports.handler = async function () {}')[0]?.kind).toBe('serverless');
    expect(detectEntrypoints('supabase/functions/send-email/index.ts', 'Deno.serve(() => new Response())')[0]?.kind).toBe('edge-function');
  });

  it('returns nothing for ordinary modules', () => {
    expect(detectEntrypoints('src/lib/math.ts', 'export const add = (a, b) => a + b;')).toEqual([]);
  });
});

describe('detectEntrypoints (Python)', () => {
  it('detects Flask/FastAPI decorators', () => {
    const src = ['app = FastAPI()', '', "@app.get('/items/{id}')", 'def read(id): ...', '@bp.route("/admin")', 'def admin(): ...'].join('\n');
    expect(detectEntrypoints('api/main.py', src)).toEqual([
      { path: 'api/main.py', kind: 'http-route', line: 3, detail: 'GET /items/{id}' },
      { path: 'api/main.py', kind: 'http-route', line: 5, detail: 'ROUTE /admin' },
    ]);
  });

  it('detects Django urls, lambda handlers and __main__ scripts', () => {
    expect(detectEntrypoints('shop/urls.py', "urlpatterns = [path('cart/', views.cart)]")[0]?.kind).toBe('django-urls');
    expect(detectEntrypoints('fn.py', 'import json\n\ndef lambda_handler(event, context):\n    pass')[0])
      .toMatchObject({ kind: 'serverless', line: 3 });
    expect(detectEntrypoints('tool.py', "def main(): ...\n\nif __name__ == '__main__':\n    main()")[0])
      .toMatchObject({ kind: 'script', line: 3 });
  });
});

describe('packageJsonBins', () => {
  it('maps string and object bin fields to repo paths', () => {
    expect(packageJsonBins('packages/cli/package.json', JSON.stringify({ name: 'acme-cli', bin: './bin/run.js' }))).toEqual([
      { path: 'packages/cli/bin/run.js', kind: 'cli', line: null, detail: 'acme-cli' },
    ]);
    expect(packageJsonBins('package.json', JSON.stringify({ bin: { a: 'dist/a.js', b: './b.js' } }))).toEqual([
      { path: 'dist/a.js', kind: 'cli', line: null, detail: 'a' },
      { path: 'b.js', kind: 'cli', line: null, detail: 'b' },
    ]);
    expect(packageJsonBins('package.json', '{ not json')).toEqual([]);
  });
});
