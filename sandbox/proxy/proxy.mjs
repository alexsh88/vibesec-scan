// VibeSec egress proxy: the ONLY network path out of a phase-A (install) sandbox container.
//
// Deliberately tiny and dependency-free so it can be audited in one sitting:
//  - only HTTP CONNECT tunnels are accepted; every plain-HTTP request (GET http://..., etc.) gets 403;
//  - the CONNECT target host must be an exact, case-insensitive match of the allowlist (no wildcards,
//    no suffix matching), IP literals are always refused, and the port must be allowlisted (443);
//  - the allowlisted name is resolved here and the connection is refused when it resolves to a
//    private / loopback / link-local / unspecified address (defense against DNS tricks);
//  - per-connection idle timeout, a hard cap on concurrent connections, every decision logged as one
//    JSON line on stdout.
//
// Configuration (environment, set by the image; the PROXY_ALLOW_* overrides exist for unit tests):
//   PROXY_PORT            listen port (default 3128; 0 = ephemeral, the chosen port is logged)
//   PROXY_HOST            listen address (default 0.0.0.0)
//   PROXY_ALLOW           comma-separated exact host allowlist
//   PROXY_ALLOW_PORTS     comma-separated port allowlist (default 443)
//   PROXY_ALLOW_PRIVATE   "1" to permit private/loopback upstream addresses (TESTS ONLY)
//   PROXY_IDLE_MS         idle timeout per connection (default 30000)
//   PROXY_MAX_CONN        max concurrent client connections (default 64)
import { lookup } from 'node:dns';
import http from 'node:http';
import net from 'node:net';
import { pathToFileURL } from 'node:url';

const DEFAULT_ALLOW = ['registry.npmjs.org', 'registry.yarnpkg.com', 'pypi.org', 'files.pythonhosted.org'];

const env = process.env;
const listToSet = (v, fallback) => new Set(
  (v ? v.split(',') : fallback).map((s) => s.trim().toLowerCase()).filter(Boolean),
);
const ALLOW = listToSet(env.PROXY_ALLOW, DEFAULT_ALLOW);
const ALLOW_PORTS = new Set([...listToSet(env.PROXY_ALLOW_PORTS, ['443'])].map(Number).filter((n) => Number.isInteger(n) && n > 0 && n < 65536));
const ALLOW_PRIVATE = env.PROXY_ALLOW_PRIVATE === '1';
const IDLE_MS = Number(env.PROXY_IDLE_MS) > 0 ? Number(env.PROXY_IDLE_MS) : 30_000;
const MAX_CONN = Number(env.PROXY_MAX_CONN) > 0 ? Number(env.PROXY_MAX_CONN) : 64;
const PORT = env.PROXY_PORT !== undefined && env.PROXY_PORT !== '' ? Number(env.PROXY_PORT) : 3128;
const HOST = env.PROXY_HOST || '0.0.0.0';
const CONNECT_TIMEOUT_MS = 10_000;

const HOSTNAME_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;

function log(fields) {
  process.stdout.write(`${JSON.stringify({ ts: new Date().toISOString(), ...fields })}\n`);
}

/** Truncates attacker-supplied text before it is logged. */
const clip = (s) => String(s).slice(0, 200);

/** Parses a CONNECT authority "host:port". Returns null when malformed. */
export function parseAuthority(authority) {
  if (typeof authority !== 'string' || authority.length > 300) return null;
  const m = /^(\[[^\]]*\]|[^:[\]]+):(\d{1,5})$/.exec(authority);
  if (!m) return null;
  const host = m[1].toLowerCase().replace(/\.$/, '');
  const port = Number(m[2]);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { host, port };
}

/** Pure allow/deny decision for a CONNECT target (before DNS). */
export function decide(host, port) {
  const bare = host.startsWith('[') ? host.slice(1, -1) : host;
  if (net.isIP(bare) !== 0) return { allow: false, reason: 'ip-literal' };
  if (!HOSTNAME_RE.test(bare)) return { allow: false, reason: 'bad-host' };
  if (!ALLOW.has(bare)) return { allow: false, reason: 'host-not-allowlisted' };
  if (!ALLOW_PORTS.has(port)) return { allow: false, reason: 'port-not-allowlisted' };
  return { allow: true, reason: 'allowlisted' };
}

/** IPv6 text → eight 16-bit groups (handles "::" and a trailing dotted quad), or null when malformed. */
function ipv6Groups(addr) {
  let v = addr.toLowerCase();
  const pct = v.indexOf('%');
  if (pct !== -1) v = v.slice(0, pct);
  const quad = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(v);
  if (quad) {
    const b = quad.slice(1).map(Number);
    if (b.some((x) => x > 255)) return null;
    v = `${v.slice(0, quad.index)}${((b[0] << 8) | b[1]).toString(16)}:${((b[2] << 8) | b[3]).toString(16)}`;
  }
  const halves = v.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  if (fill < 0 || (halves.length === 1 && head.length !== 8)) return null;
  const groups = [...head, ...Array(fill).fill('0'), ...tail].map((g) => (/^[0-9a-f]{1,4}$/.test(g) ? parseInt(g, 16) : NaN));
  return groups.length === 8 && groups.every((g) => Number.isInteger(g)) ? groups : null;
}

/** True for addresses an allowlisted public registry must never resolve to. */
export function isPrivateAddress(addr) {
  if (net.isIPv4(addr)) {
    const [a, b, c] = addr.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224
      || (a === 198 && (b === 18 || b === 19)) // 198.18.0.0/15 benchmarking (often internal)
      || (a === 192 && b === 0 && c === 0); // 192.0.0.0/24 IETF protocol assignments
  }
  const g = ipv6Groups(addr);
  if (!g) return true; // unparseable: refuse
  const [g0, g1, g2, g3, g4, g5, g6, g7] = g;
  const v4 = `${g6 >> 8}.${g6 & 255}.${g7 >> 8}.${g7 & 255}`;
  if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0) {
    if (g5 === 0xffff) return isPrivateAddress(v4); // ::ffff:a.b.c.d (v4-mapped)
    if (g5 === 0) return true; // ::, ::1 and ::a.b.c.d (deprecated v4-compatible)
  }
  if (g0 === 0x64 && g1 === 0xff9b) return true; // NAT64 64:ff9b::/96 and 64:ff9b:1::/48 (reach v4 internals)
  if (g0 === 0x2002) return true; // 6to4 2002::/16 (embeds an arbitrary v4)
  if (g0 === 0x2001 && g1 === 0x0db8) return true; // documentation
  if (g0 === 0x0100 && g1 === 0 && g2 === 0 && g3 === 0) return true; // discard-only 100::/64
  return (g0 & 0xfe00) === 0xfc00 // fc00::/7 unique local
    || (g0 & 0xffc0) === 0xfe80 // fe80::/10 link-local
    || (g0 & 0xffc0) === 0xfec0 // fec0::/10 site-local (deprecated)
    || (g0 & 0xff00) === 0xff00; // multicast
}

/** dns.lookup wrapper that refuses private answers (unless PROXY_ALLOW_PRIVATE=1, tests only). */
function guardedLookup(hostname, options, callback) {
  lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return callback(err);
    const list = Array.isArray(addresses) ? addresses : [{ address: addresses, family: options.family || 4 }];
    if (!ALLOW_PRIVATE && list.some((a) => isPrivateAddress(a.address))) {
      const e = new Error(`refusing private address for ${hostname}`);
      e.code = 'EPRIVATE';
      return callback(e);
    }
    const first = list[0];
    if (!first) return callback(new Error(`no address for ${hostname}`));
    if (options.all) return callback(null, list);
    return callback(null, first.address, first.family);
  });
}

let active = 0;

function reject(socket, status, text) {
  if (socket.destroyed) return;
  socket.end(`HTTP/1.1 ${status} ${text}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
  setTimeout(() => socket.destroy(), 1_000).unref();
}

const server = http.createServer({ requestTimeout: 10_000, headersTimeout: 10_000, maxHeaderSize: 8_192 }, (req, res) => {
  // Plain HTTP forwarding is never offered: registries are HTTPS-only and tunnels are auditable.
  log({ decision: 'deny', method: clip(req.method), target: clip(req.url), reason: 'plain-http' });
  res.writeHead(403, { 'Content-Type': 'text/plain', Connection: 'close' });
  res.end('vibesec proxy: plain HTTP is not allowed\n');
});

server.on('connection', (socket) => {
  if (active >= MAX_CONN) {
    log({ decision: 'deny', reason: 'too-many-connections' });
    socket.destroy();
    return;
  }
  active += 1;
  socket.once('close', () => { active -= 1; });
  socket.setTimeout(IDLE_MS, () => socket.destroy());
  socket.on('error', () => socket.destroy());
});

server.on('connect', (req, client, head) => {
  const target = parseAuthority(req.url);
  if (!target) {
    log({ decision: 'deny', target: clip(req.url), reason: 'malformed-target' });
    return reject(client, 400, 'Bad Request');
  }
  const verdict = decide(target.host, target.port);
  if (!verdict.allow) {
    log({ decision: 'deny', host: clip(target.host), port: target.port, reason: verdict.reason });
    return reject(client, 403, 'Forbidden');
  }

  const upstream = net.connect({ host: target.host, port: target.port, lookup: guardedLookup, timeout: CONNECT_TIMEOUT_MS });
  let established = false;
  upstream.once('connect', () => {
    established = true;
    upstream.setTimeout(IDLE_MS, () => upstream.destroy());
    log({ decision: 'allow', host: target.host, port: target.port, remote: upstream.remoteAddress });
    client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head && head.length) upstream.write(head);
    upstream.pipe(client);
    client.pipe(upstream);
  });
  upstream.once('timeout', () => upstream.destroy(new Error('connect timeout')));
  upstream.on('error', (err) => {
    if (!established) {
      log({ decision: 'deny', host: target.host, port: target.port, reason: err.code === 'EPRIVATE' ? 'private-address' : 'upstream-error', error: clip(err.code || err.message) });
      reject(client, err.code === 'EPRIVATE' ? 403 : 502, err.code === 'EPRIVATE' ? 'Forbidden' : 'Bad Gateway');
    } else {
      client.destroy();
    }
  });
  client.on('close', () => upstream.destroy());
  upstream.on('close', () => client.destroy());
});

server.on('clientError', (_err, socket) => reject(socket, 400, 'Bad Request'));

server.maxConnections = MAX_CONN;

// Listen only when run as the entry point, so unit tests can import the pure helpers above.
const isMain = process.argv[1] !== undefined && pathToFileURL(process.argv[1]).href === import.meta.url;
if (isMain) {
  server.listen(PORT, HOST, () => {
    const addr = server.address();
    log({ event: 'listening', port: typeof addr === 'object' && addr ? addr.port : PORT, allow: [...ALLOW], ports: [...ALLOW_PORTS] });
  });
  const stop = () => server.close(() => process.exit(0));
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
}
