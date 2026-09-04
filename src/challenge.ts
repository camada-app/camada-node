// The challenge for @camada/node (SDK-04). node:crypto gives us a synchronous HMAC, so the
// cookie check costs nothing on the hot path and Camada.handle() stays a synchronous boolean.
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createHash, createHmac } from 'node:crypto';
import { createChallenge, type ChallengeKit } from '@camada/core';

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

export const isHttps = (req: IncomingMessage): boolean =>
  !!(req.socket as { encrypted?: boolean } | undefined)?.encrypted || req.headers['x-forwarded-proto'] === 'https';

export function writeChallengePage(res: ServerResponse, html: string): void {
  res.writeHead(403, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-camada-challenge': '1' });
  res.end(html);
}

export function writeChallengeJson(res: ServerResponse): void {
  res.writeHead(403, { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-camada-challenge': '1' });
  res.end('{"error":"challenge_required"}');
}
