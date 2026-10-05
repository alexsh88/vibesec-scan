import { spawn, type ChildProcess } from 'node:child_process';
import net from 'node:net';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const PROXY = resolve(REPO_ROOT, 'sandbox', 'proxy', 'proxy.mjs');

type Proxy = { child: ChildProcess; port: number; logs: string[] };

function startProxy(extraEnv: Record<string, string>): Promise<Proxy> {
  return new Promise((res, rej) => {
    const child = spawn(process.execPath, [PROXY], {
      env: { PROXY_PORT: '0', PROXY_HOST: '127.0.0.1', ...extraEnv }, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
    });
    const logs: string[] = [];
    let buf = '';
    const timer = setTimeout(() => rej(new Error('proxy did not start')), 5_000);
    child.stdout!.on('data', (d: Buffer) => {
      buf += d.toString('utf8');
      const lines = buf.split('\n');
      buf = lines.pop() ?? '';
      for (const line of lines) {
        logs.push(line);
        const msg = JSON.parse(line) as { event?: string; port?: number };
        if (msg.event === 'listening' && msg.port) { clearTimeout(timer); res({ child, port: msg.port, logs }); }
      }
    });
    child.on('error', rej);
  });
}

/** Sends raw bytes and returns everything received until the first response head (or close). */
function rawRequest(port: number, payload: string, then?: string): Promise<{ head: string; body: string }> {
  return new Promise((res, rej) => {
    const sock = net.connect(port, '127.0.0.1');
    let data = '';
    let sentFollowUp = false;
    sock.setTimeout(4_000, () => { sock.destroy(); res(split(data)); });
    sock.on('connect', () => sock.write(payload));
    sock.on('data', (d) => {
      data += d.toString('utf8');
      if (then && !sentFollowUp && data.includes('\r\n\r\n')) {
        sentFollowUp = true;
        if (/^HTTP\/1\.1 200/.test(data)) sock.write(then);
        else { sock.destroy(); res(split(data)); }
      } else if (then && sentFollowUp && data.includes('ECHO:')) {
        sock.destroy(); res(split(data));
      }
    });
    sock.on('end', () => res(split(data)));
    sock.on('close', () => res(split(data)));
    sock.on('error', rej);
  });
}
const split = (data: string) => {
  const i = data.indexOf('\r\n\r\n');
  return i < 0 ? { head: data, body: '' } : { head: data.slice(0, i), body: data.slice(i + 4) };
};

let upstream: net.Server;
let upstreamPort = 0;
let proxy: Proxy;
let strictProxy: Proxy;

beforeAll(async () => {
  upstream = net.createServer((s) => s.on('data', (d) => s.write(`ECHO:${d.toString('utf8')}`)));
  await new Promise<void>((r) => upstream.listen(0, '127.0.0.1', r));
  upstreamPort = (upstream.address() as net.AddressInfo).port;
  // Test-only overrides: allow the loopback fake upstream by NAME (IP literals stay forbidden).
  proxy = await startProxy({ PROXY_ALLOW: 'localhost', PROXY_ALLOW_PORTS: String(upstreamPort), PROXY_ALLOW_PRIVATE: '1' });
  // Same allowlist but with the production private-address guard on.
  strictProxy = await startProxy({ PROXY_ALLOW: 'localhost', PROXY_ALLOW_PORTS: String(upstreamPort) });
});

afterAll(() => {
  proxy?.child.kill();
  strictProxy?.child.kill();
  upstream?.close();
});

describe('sandbox egress proxy', () => {
  it('tunnels CONNECT to an allowlisted host and port', async () => {
    const r = await rawRequest(proxy.port, `CONNECT localhost:${upstreamPort} HTTP/1.1\r\nHost: localhost:${upstreamPort}\r\n\r\n`, 'hello');
    expect(r.head).toMatch(/^HTTP\/1\.1 200/);
    expect(r.body).toContain('ECHO:hello');
  });

  it('refuses a host that is not allowlisted with 403', async () => {
    const r = await rawRequest(proxy.port, 'CONNECT evil.example.com:443 HTTP/1.1\r\nHost: evil.example.com:443\r\n\r\n');
    expect(r.head).toMatch(/^HTTP\/1\.1 403/);
  });

  it('refuses suffix tricks (allowlisted name as a label of another domain)', async () => {
    const r = await rawRequest(proxy.port, 'CONNECT localhost.evil.example:443 HTTP/1.1\r\n\r\n');
    expect(r.head).toMatch(/^HTTP\/1\.1 403/);
  });

  it('refuses IPv4 and IPv6 literals with 403 even on an allowed port', async () => {
    const v4 = await rawRequest(proxy.port, `CONNECT 127.0.0.1:${upstreamPort} HTTP/1.1\r\n\r\n`);
    expect(v4.head).toMatch(/^HTTP\/1\.1 403/);
    const v6 = await rawRequest(proxy.port, `CONNECT [::1]:${upstreamPort} HTTP/1.1\r\n\r\n`);
    expect(v6.head).toMatch(/^HTTP\/1\.1 403/);
  });

  it('refuses an allowlisted host on a non-allowlisted port (e.g. 80)', async () => {
    const r = await rawRequest(proxy.port, 'CONNECT localhost:80 HTTP/1.1\r\n\r\n');
    expect(r.head).toMatch(/^HTTP\/1\.1 403/);
  });

  it('refuses plain HTTP forwarding with 403', async () => {
    const r = await rawRequest(proxy.port, `GET http://localhost:${upstreamPort}/ HTTP/1.1\r\nHost: localhost:${upstreamPort}\r\n\r\n`);
    expect(r.head).toMatch(/^HTTP\/1\.1 403/);
  });

  it('refuses an allowlisted name that resolves to a private address (production guard)', async () => {
    const r = await rawRequest(strictProxy.port, `CONNECT localhost:${upstreamPort} HTTP/1.1\r\n\r\n`);
    expect(r.head).toMatch(/^HTTP\/1\.1 403/);
  });

  it('logs every decision as a JSON line', async () => {
    await rawRequest(proxy.port, 'CONNECT denied.example:443 HTTP/1.1\r\n\r\n');
    await new Promise((r) => setTimeout(r, 100));
    const decisions = proxy.logs.map((l) => JSON.parse(l) as { decision?: string; host?: string; reason?: string });
    expect(decisions).toContainEqual(expect.objectContaining({ decision: 'deny', host: 'denied.example', reason: 'host-not-allowlisted' }));
    expect(decisions).toContainEqual(expect.objectContaining({ decision: 'allow', host: 'localhost' }));
  });
});

describe('isPrivateAddress (DNS-answer guard)', () => {
  const load = async () => (await import(pathToFileURL(PROXY).href)) as { isPrivateAddress: (a: string) => boolean };

  it('refuses every non-public range, including v6 encodings of v4 internals', async () => {
    const { isPrivateAddress } = await load();
    for (const a of [
      '10.1.2.3', '127.0.0.1', '169.254.169.254', '172.16.0.1', '192.168.1.1', '100.64.0.1', '0.0.0.0', '224.0.0.1',
      '198.18.0.1', '198.19.255.255', '192.0.0.8',
      '::', '::1', '::ffff:127.0.0.1', '::ffff:7f00:1', '::127.0.0.1', '::a00:1',
      '64:ff9b::a00:1', '64:ff9b::10.0.0.1', '64:ff9b:1::1', '2002:a00:1::1', '2002::',
      'fc00::1', 'fd12:3456::1', 'fe80::1', 'febf::1', 'fec0::1', 'feff::1', 'ff02::1', '2001:db8::1', '100::1',
      'not-an-ip', '1::2::3',
    ]) expect(isPrivateAddress(a), a).toBe(true);
  });

  it('allows public addresses', async () => {
    const { isPrivateAddress } = await load();
    for (const a of ['104.16.0.35', '151.101.0.223', '198.20.0.1', '192.0.1.1', '2606:4700::6810:84e5', '2a04:4e42::223', '::ffff:151.101.0.223']) {
      expect(isPrivateAddress(a), a).toBe(false);
    }
  });
});
