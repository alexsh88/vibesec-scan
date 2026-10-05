import { createHash, createHmac } from 'node:crypto';

export type SignV4Request = {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string;
  region: string;
  service: string;
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  now: Date;
};

const ALGORITHM = 'AWS4-HMAC-SHA256';

/** YYYYMMDDTHHMMSSZ, per AWS SigV4. */
function amzDate(d: Date): string {
  return d.toISOString().replace(/[:-]|\.\d{3}/g, '');
}

function sha256Hex(data: string): string {
  return createHash('sha256').update(data, 'utf8').digest('hex');
}

function hmac(key: Buffer | string, data: string): Buffer {
  return createHmac('sha256', key).update(data, 'utf8').digest();
}

/** AWS's URI-encoding: RFC 3986 unreserved set left bare, everything else percent-encoded (uppercase hex). */
function awsUriEncode(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

function canonicalUri(pathname: string): string {
  const path = pathname === '' ? '/' : pathname;
  return path.split('/').map(awsUriEncode).join('/');
}

function canonicalQueryString(url: URL): string {
  const pairs: Array<[string, string]> = [];
  for (const [k, v] of url.searchParams.entries()) pairs.push([awsUriEncode(k), awsUriEncode(v)]);
  pairs.sort(([ka, va], [kb, vb]) => (ka === kb ? (va < vb ? -1 : va > vb ? 1 : 0) : ka < kb ? -1 : 1));
  return pairs.map(([k, v]) => `${k}=${v}`).join('&');
}

function canonicalHeaders(headers: Record<string, string>): { signedHeaders: string; canonicalHeadersBlock: string } {
  const normalized = new Map<string, string>();
  for (const [name, value] of Object.entries(headers)) {
    normalized.set(name.toLowerCase(), value.trim().replace(/\s+/g, ' '));
  }
  const sortedNames = [...normalized.keys()].sort();
  const canonicalHeadersBlock = sortedNames.map((name) => `${name}:${normalized.get(name) ?? ''}\n`).join('');
  return { signedHeaders: sortedNames.join(';'), canonicalHeadersBlock };
}

/**
 * Standard AWS Signature Version 4 (see AWS SigV4 test suite). Returns the headers to send,
 * including `host`, `x-amz-date` (and `x-amz-security-token` when a session token is given)
 * and `authorization`. Never includes the secret key material in its output.
 */
export function signV4(req: SignV4Request): Record<string, string> {
  const url = new URL(req.url);
  const amzdate = amzDate(req.now);
  const datestamp = amzdate.slice(0, 8);

  const headersToSign: Record<string, string> = { ...req.headers, host: url.host, 'x-amz-date': amzdate };
  if (req.sessionToken) headersToSign['x-amz-security-token'] = req.sessionToken;

  const { signedHeaders, canonicalHeadersBlock } = canonicalHeaders(headersToSign);
  const payloadHash = sha256Hex(req.body);

  const canonicalRequest = [
    req.method.toUpperCase(),
    canonicalUri(url.pathname),
    canonicalQueryString(url),
    canonicalHeadersBlock,
    signedHeaders,
    payloadHash,
  ].join('\n');

  const credentialScope = `${datestamp}/${req.region}/${req.service}/aws4_request`;
  const stringToSign = [ALGORITHM, amzdate, credentialScope, sha256Hex(canonicalRequest)].join('\n');

  const kDate = hmac(`AWS4${req.secretAccessKey}`, datestamp);
  const kRegion = hmac(kDate, req.region);
  const kService = hmac(kRegion, req.service);
  const kSigning = hmac(kService, 'aws4_request');
  const signature = hmac(kSigning, stringToSign).toString('hex');

  const authorization =
    `${ALGORITHM} Credential=${req.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  return { ...headersToSign, authorization };
}
