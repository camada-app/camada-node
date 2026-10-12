// The challenge for @camada/node (SDK-04). node:crypto gives us a synchronous HMAC, so the
// cookie check costs nothing on the hot path and Camada.handle() stays a synchronous boolean.
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createHash, createHmac } from 'node:crypto';
import { createChallenge, challengePageCsp, parseFormBody, type ChallengeKit } from '@camada/core';

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

/** The verify POST's form fields, always delivered (never leaves the request hanging). A body
 *  parser mounted before camada (express.urlencoded(), always on Nest) has already drained the
 *  stream, so its `'end'` will never fire again: use what it left on `req.body` (an object from
 *  urlencoded/json, or a string/Buffer from text/raw). A drained stream with nothing usable
 *  yields {}, which fails verification and re-serves the page at once. */
export function readForm(req: IncomingMessage & { body?: unknown }, done: (form: Record<string, string>) => void): void {
  if (!req.readableEnded) { readBody(req, (body) => done(parseFormBody(body))); return; }
  const b = req.body;
  if (typeof b === 'string' || Buffer.isBuffer(b)) { done(b.length > BODY_MAX ? {} : parseFormBody(b.toString())); return; }
  const form: Record<string, string> = Object.create(null);
  if (b && typeof b === 'object') {
    for (const k of FORM_FIELDS) {
      const v = (b as Record<string, unknown>)[k];
      if (typeof v === 'string') form[k] = v;
    }
  }
  done(form);
}

export const isHttps = (req: IncomingMessage): boolean =>
  !!(req.socket as { encrypted?: boolean } | undefined)?.encrypted || req.headers['x-forwarded-proto'] === 'https';

/** The page brings its own CSP (only its inline solver and style, by hash): a policy the app set
 *  earlier (helmet before camada) would otherwise ride along on this response and block the solver. */
export function writeChallengePage(res: ServerResponse, html: string): void {
  res.removeHeader('content-security-policy');
  res.removeHeader('content-security-policy-report-only');
  res.writeHead(403, {
    'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-camada-challenge': '1',
    'content-security-policy': challengePageCsp(),
  });
  res.end(html);
}

export function writeChallengeJson(res: ServerResponse): void {
  res.writeHead(403, { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-camada-challenge': '1' });
  res.end('{"error":"challenge_required"}');
}
