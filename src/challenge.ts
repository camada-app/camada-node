// The challenge for @camada/node (SDK-04). node:crypto gives us a synchronous HMAC, so the
// cookie check costs nothing on the hot path and Camada.handle() stays a synchronous boolean.
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createHash, createHmac } from 'node:crypto';
import { createChallenge, challengePage, challengePageCsp, parseFormBody, type ChallengeKit, type ChallengePageOptions } from '@camada/core';

export const CHALLENGE_PATH = '/__camada/challenge';
const BODY_MAX = 4 * 1024;   // the verify form is ~120 bytes; anything larger is not ours

export function nodeChallengeKit(secret: string): ChallengeKit {
  return createChallenge({
    secret,
    hmac: (s, m) => createHmac('sha256', s).update(m).digest('hex'),
    sha: (m) => createHash('sha256').update(m).digest('hex'),
  });
}

/** Reads at most BODY_MAX bytes; hands back '' when the client sends more (or errors). */
export function readBody(req: IncomingMessage, done: (body: string) => void): void {
  const chunks: Buffer[] = [];
  let size = 0, dead = false;
  req.on('data', (c: Buffer) => {
    if (dead) return;
    size += c.length;
    if (size > BODY_MAX) { dead = true; chunks.length = 0; return; }
    chunks.push(c);
  });
  req.on('end', () => done(dead ? '' : Buffer.concat(chunks).toString('utf8')));
  req.on('error', () => done(''));
}

const FORM_FIELDS = ['nonce', 'solution', 'to'] as const;

/** What a body parser mounted before camada left on `req.body` once it drained the stream: the
 *  text of a string/Buffer body (text/raw parsers), the object of a parsed one (json, urlencoded,
 *  Koa's parsers via the adapter), or null when nothing usable is left. */
export function parsedBody(req: IncomingMessage & { body?: unknown }): string | Record<string, unknown> | null {
  const b = req.body;
  if (typeof b === 'string') return b;
  if (Buffer.isBuffer(b)) return b.toString('utf8');
  return b && typeof b === 'object' ? (b as Record<string, unknown>) : null;
}

/** The verify POST's form fields, always delivered (never leaves the request hanging). A body
 *  parser mounted before camada (express.urlencoded(), always on Nest) has already drained the
 *  stream, so its `'end'` will never fire again: use what it left behind (parsedBody). Only
 *  string fields count. A drained stream with nothing usable, or an oversized one, yields {},
 *  which fails verification and re-serves the page at once. */
export function readForm(req: IncomingMessage & { body?: unknown }, done: (form: Record<string, string>) => void): void {
  if (!req.readableEnded) { readBody(req, (body) => done(parseFormBody(body))); return; }
  const b = parsedBody(req);
  if (typeof b === 'string') { done(b.length > BODY_MAX ? {} : parseFormBody(b)); return; }
  const form: Record<string, string> = Object.create(null);
  for (const k of FORM_FIELDS) {
    const v = b?.[k];
    if (typeof v === 'string') form[k] = v;
  }
  done(form);
}

export const isHttps = (req: IncomingMessage): boolean =>
  !!(req.socket as { encrypted?: boolean } | undefined)?.encrypted || req.headers['x-forwarded-proto'] === 'https';

/** Writes `challengePage(o)` with its own CSP for the same `bits` (only its inline solver and
 *  style, by hash): a policy the app set earlier (helmet before camada) would otherwise ride along
 *  on this response and block the solver. */
export function writeChallengePage(res: ServerResponse, o: ChallengePageOptions): void {
  res.removeHeader('content-security-policy');
  res.removeHeader('content-security-policy-report-only');
  res.writeHead(403, {
    'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-camada-challenge': '1',
    'content-security-policy': challengePageCsp(o.bits),
  });
  res.end(challengePage(o));
}
