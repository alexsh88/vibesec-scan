// Package name ↔ import name mapping, used to match source-code usages (index imports or sandbox
// usage reports) to dependency-graph nodes, and to build the sandbox analyzers' `importNames` input.
//
// npm: a package is imported under its own name (consumers match the name exactly or as a
// `name/` subpath prefix). PyPI: a distribution is imported under one or more top-level module
// names that often differ from the distribution name (pyyaml → yaml). P2's index maps imports to
// distributions with IMPORT_TO_DISTRIBUTION; this module is its reverse, extended with more
// well-known distributions.

import { IMPORT_TO_DISTRIBUTION } from '../../index/pyImports';
import { normalizePypiName } from './lockfiles/graph';
import type { Ecosystem } from './types';

/** Distribution (PEP 503-normalized) → module names, where they differ from the default. */
const EXTRA_DISTRIBUTION_MODULES: Record<string, string[]> = {
  'pyyaml': ['yaml'],
  'beautifulsoup4': ['bs4'],
  'pillow': ['PIL'],
  'scikit-learn': ['sklearn'],
  'scikit-image': ['skimage'],
  'python-dateutil': ['dateutil'],
  'opencv-python': ['cv2'],
  'opencv-python-headless': ['cv2'],
  'opencv-contrib-python': ['cv2'],
  'opencv-contrib-python-headless': ['cv2'],
  'python-dotenv': ['dotenv'],
  'pyjwt': ['jwt'],
  'python-jose': ['jose'],
  'pycryptodome': ['Crypto'],
  'pycryptodomex': ['Cryptodome'],
  'pyopenssl': ['OpenSSL'],
  'python-magic': ['magic'],
  'python-multipart': ['multipart'],
  'psycopg2-binary': ['psycopg2'],
  'psycopg-binary': ['psycopg'],
  'mysqlclient': ['MySQLdb'],
  'pymysql': ['pymysql'],
  'attrs': ['attr', 'attrs'],
  'pyserial': ['serial'],
  'pyusb': ['usb'],
  'python-telegram-bot': ['telegram'],
  'python-docx': ['docx'],
  'python-pptx': ['pptx'],
  'gitpython': ['git'],
  'kafka-python': ['kafka'],
  'pytest': ['pytest', '_pytest'],
  'protobuf': ['google.protobuf'],
  'google-api-core': ['google.api_core'],
  'google-auth': ['google.auth', 'google.oauth2'],
  'google-cloud-storage': ['google.cloud.storage'],
  'google-cloud-bigquery': ['google.cloud.bigquery'],
  'google-api-python-client': ['googleapiclient'],
  'setuptools': ['setuptools', 'pkg_resources'],
  'pyzmq': ['zmq'],
  'python-ldap': ['ldap'],
  'ruamel-yaml': ['ruamel.yaml'],
  'dnspython': ['dns'],
  'pysocks': ['socks'],
  'faiss-cpu': ['faiss'],
  'faiss-gpu': ['faiss'],
  'msgpack-python': ['msgpack'],
  'pywin32': ['win32api', 'win32con', 'win32com', 'pywintypes'],
  'pyqt5': ['PyQt5'],
  'pyqt6': ['PyQt6'],
  'markupsafe': ['markupsafe'],
  'jinja2': ['jinja2'],
  'pygithub': ['github'],
  'python-slugify': ['slugify'],
  'python-json-logger': ['pythonjsonlogger'],
  'websocket-client': ['websocket'],
  'email-validator': ['email_validator'],
  'pymupdf': ['fitz', 'pymupdf'],
  'tensorflow-gpu': ['tensorflow'],
  'tensorflow-cpu': ['tensorflow'],
  'grpcio': ['grpc'],
  'grpcio-tools': ['grpc_tools'],
  'azure-storage-blob': ['azure.storage.blob'],
  'azure-identity': ['azure.identity'],
  'paho-mqtt': ['paho.mqtt'],
  'beautifulsoup': ['BeautifulSoup'],
  'pycrypto': ['Crypto'],
};

function buildDistributionModules(): Map<string, string[]> {
  const map = new Map<string, string[]>();
  for (const [module, dist] of Object.entries(IMPORT_TO_DISTRIBUTION)) {
    const key = normalizePypiName(dist);
    if (key === 'google-api-core' || module === '_pytest') continue; // too broad / covered below
    const list = map.get(key) ?? [];
    if (!list.includes(module)) list.push(module);
    map.set(key, list);
  }
  for (const [dist, modules] of Object.entries(EXTRA_DISTRIBUTION_MODULES)) map.set(normalizePypiName(dist), [...modules]);
  return map;
}

const DISTRIBUTION_MODULES = buildDistributionModules();

/** Module name (exact, possibly dotted) → distribution, the reverse of DISTRIBUTION_MODULES. */
const MODULE_TO_DISTRIBUTION: Map<string, string> = (() => {
  const m = new Map<string, string>();
  for (const [dist, modules] of DISTRIBUTION_MODULES) for (const mod of modules) if (!m.has(mod)) m.set(mod, dist);
  for (const [mod, dist] of Object.entries(IMPORT_TO_DISTRIBUTION)) if (!m.has(mod)) m.set(mod, normalizePypiName(dist));
  return m;
})();

/** Default module name for a PyPI distribution without a known mapping. */
function defaultModule(name: string): string {
  return normalizePypiName(name).replace(/-/g, '_');
}

/**
 * Names under which `name` is imported by application code. npm: `[name]` (consumers also match
 * `name/…` subpaths). PyPI: the module names the distribution installs (possibly dotted, e.g.
 * `google.protobuf`; consumers also match `module.…` sub-modules).
 */
export function importNamesFor(ecosystem: Ecosystem, name: string): string[] {
  if (ecosystem === 'npm') return [name];
  const dist = normalizePypiName(name);
  const mapped = DISTRIBUTION_MODULES.get(dist);
  return mapped ? [...mapped] : [defaultModule(dist)];
}

/** npm package root of a module specifier: `@scope/pkg/sub` → `@scope/pkg`, `pkg/sub` → `pkg`. */
export function npmPackageRoot(specifier: string): string {
  const segments = specifier.split('/');
  return specifier.startsWith('@') ? segments.slice(0, 2).join('/') : (segments[0] ?? specifier);
}

/**
 * Maps an import specifier / module name (or a value that is already a package name, as P2's index
 * rows carry) back to one of `knownPackages`, or null when none matches. npm: the longest known
 * package that equals the specifier or is a `/`-prefix of it. PyPI: the longest dotted prefix of the
 * module that is a known import name of one of the known distributions.
 */
export function packageForImport(ecosystem: Ecosystem, specifier: string, knownPackages: Iterable<string>): string | null {
  if (ecosystem === 'npm') {
    let best: string | null = null;
    for (const pkg of knownPackages) {
      if ((specifier === pkg || specifier.startsWith(`${pkg}/`)) && (best === null || pkg.length > best.length)) best = pkg;
    }
    return best;
  }

  // PyPI: index all import names of the known distributions.
  const byModule = new Map<string, string>();
  const byDist = new Map<string, string>();
  for (const pkg of knownPackages) {
    const dist = normalizePypiName(pkg);
    byDist.set(dist, pkg);
    for (const mod of importNamesFor('PyPI', pkg)) if (!byModule.has(mod)) byModule.set(mod, pkg);
  }
  const parts = specifier.split('.');
  for (let n = parts.length; n >= 1; n--) {
    const mod = parts.slice(0, n).join('.');
    const hit = byModule.get(mod);
    if (hit !== undefined) return hit;
  }
  // Already a distribution name (index rows), or a module whose distribution is known.
  const asDist = byDist.get(normalizePypiName(specifier));
  if (asDist !== undefined) return asDist;
  const top = parts[0] ?? specifier;
  const viaMap = MODULE_TO_DISTRIBUTION.get(top);
  if (viaMap !== undefined) return byDist.get(viaMap) ?? null;
  return byDist.get(normalizePypiName(top)) ?? null;
}
