// SDK-04 end to end over a real node:http server and the v4 golden snapshot: the page is
// served, its proof of work is solved with node:crypto, the verify endpoint sets `_cch`, and
// the cookie lets the next request through.
import { describe, it, expect, afterEach } from 'vitest';
import { createHash } from 'node:crypto';
import { CHALLENGE_COOKIE } from '@camada/core';
import type { Camada } from '../src/index.js';
import {
  fakeAnalyst, engineWith, loaded, serve, settle, BLOCKED_IP, CHALLENGED_IP, ALLOWED_IP,
  type App, type FakeAnalyst,
} from './harness.js';

const open: Array<App | Camada> = [];
afterEach(async () => { for (const o of open.splice(0)) { 'close' in o ? await o.close() : o.stop(); } });

/** A v4-serving analyst plus an app that only ever answers 200 when camada lets it through. */
async function v4App(opts: Parameters<typeof engineWith>[2] = {}) {
  const a = fakeAnalyst();
  a.v4 = true;
  const engine = engineWith(a, { CAMADA_TRUSTED_PROXY: 'hops:1' }, opts);
  await loaded(engine);
  const app = await serve((req, res) => {
    if (engine.handle(req, res)) return;
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<html><body>app</body></html>');
  });
  open.push(app, engine);
  a.events.length = 0;
  return { a, engine, app };
}

const html = { accept: 'text/html', 'sec-fetch-dest': 'document' };
const nonceOf = (page: string) => /name="nonce" value="([0-9a-f]{32})"/.exec(page)![1];
const solve = (nonce: string): string => {
  for (let n = 0; ; n++) if (createHash('sha256').update(`${nonce}.${n}`).digest('hex').startsWith('0000')) return String(n);
};

const verify = (app: App, body: string, headers: Record<string, string> = {}) =>
  fetch(`${app.url}/__camada/challenge`, {
    method: 'POST',
    redirect: 'manual',
    headers: { 'x-forwarded-for': CHALLENGED_IP, 'content-type': 'application/x-www-form-urlencoded', ...headers },
    body,
  });

/** Serves the page for `path`, solves it, and returns the verify response. */
async function pass(app: App, path = '/cart') {
  const page = await fetch(`${app.url}${path}`, { headers: { ...html, 'x-forwarded-for': CHALLENGED_IP } });
  const nonce = nonceOf(await page.text());
  return verify(app, `nonce=${nonce}&solution=${solve(nonce)}&to=${encodeURIComponent(path)}`);
}

const events = (a: FakeAnalyst) => a.events.flat() as Array<Record<string, unknown>>;

describe('serving the challenge', () => {
  it('answers 403 with the proof-of-work page and ships blk: challenge', async () => {
    const { a, engine, app } = await v4App();
    const r = await fetch(`${app.url}/cart?ref=x`, { headers: { ...html, 'x-forwarded-for': CHALLENGED_IP } });
    expect(r.status).toBe(403);
    expect(r.headers.get('content-type')).toContain('text/html');
    expect(r.headers.get('cache-control')).toBe('no-store');
    expect(r.headers.get('x-camada-challenge')).toBe('1');
    const body = await r.text();
    expect(body).toContain('Checking your browser');
    expect(body).toContain('value="/cart?ref=x"');   // it comes back to the original URL
    await engine.queue!.flush();
    expect(events(a).at(-1)).toMatchObject({ st: 403, blk: 'challenge', p: '/cart', tap: 'sdk-node' });
  });

  it('answers 403 JSON for a non-HTML request', async () => {
    const { app } = await v4App();
    const r = await fetch(`${app.url}/checkout`, { headers: { accept: 'application/json', 'x-forwarded-for': CHALLENGED_IP } });
    expect(r.status).toBe(403);
    expect(r.headers.get('content-type')).toContain('application/json');
    expect(await r.json()).toEqual({ error: 'challenge_required' });
  });

  it('answers 403 JSON when sec-fetch-dest is not a document', async () => {
    const { app } = await v4App();
    const r = await fetch(`${app.url}/checkout`, { headers: { accept: 'text/html', 'sec-fetch-dest': 'empty', 'x-forwarded-for': CHALLENGED_IP } });
    expect(await r.json()).toEqual({ error: 'challenge_required' });
  });

  it('challenges on a path rule, not just an ip', async () => {
    const { app } = await v4App();
    const r = await fetch(`${app.url}/admin/users`, { headers: { ...html, 'x-forwarded-for': '8.8.8.8' } });
    expect(r.status).toBe(403);
    expect(r.headers.get('x-camada-challenge')).toBe('1');
  });

  it('blocks outright rather than challenging when the ip is on the block side', async () => {
    const { app } = await v4App();
    const r = await fetch(`${app.url}/`, { headers: { ...html, 'x-forwarded-for': BLOCKED_IP } });
    expect(r.status).toBe(403);
    expect(r.headers.get('x-block-reason')).toBe('ip4');
    expect(r.headers.get('x-camada-challenge')).toBeNull();
  });

  it('honours the v4 allow side over a wider block', async () => {
    const { app } = await v4App();
    const r = await fetch(`${app.url}/`, { headers: { ...html, 'x-forwarded-for': ALLOWED_IP } });
    expect(r.status).toBe(200);
  });

  it('asks the server for the v4 snapshot', async () => {
    const { a } = await v4App();
    expect(a.snapshotVersions[0]).toBe('4');
  });

  it('joins the challenge rows to the session that produced them', async () => {
    const { a, engine, app } = await v4App();
    await fetch(`${app.url}/cart`, { headers: { ...html, cookie: '_sfp=known-sid', 'x-forwarded-for': CHALLENGED_IP } });
    await engine.queue!.flush();
    expect(events(a).at(-1)).toMatchObject({ blk: 'challenge', sid: 'known-sid' });
  });

  it('refuses an oversized verify body instead of buffering it', async () => {
    const { app } = await v4App();
    const r = await verify(app, `nonce=x&solution=1&to=%2F&pad=${'a'.repeat(5000)}`);
    expect(r.status).not.toBe(302);
    expect(r.headers.get('set-cookie')).toBeNull();
  });

  it('does nothing when CAMADA_CHALLENGE=0', async () => {
    const a = fakeAnalyst();
    a.v4 = true;
    const engine = engineWith(a, { CAMADA_TRUSTED_PROXY: 'hops:1', CAMADA_CHALLENGE: '0' });
    await loaded(engine);
    const app = await serve((req, res) => {
      if (engine.handle(req, res)) return;
      res.writeHead(200).end('app');
    });
    open.push(app, engine);
    const r = await fetch(`${app.url}/cart`, { headers: { ...html, 'x-forwarded-for': CHALLENGED_IP } });
    expect(r.status).toBe(200);
  });

  it('does nothing when challenge: false', async () => {
    const { app } = await v4App({ challenge: false });
    const r = await fetch(`${app.url}/cart`, { headers: { ...html, 'x-forwarded-for': CHALLENGED_IP } });
    expect(r.status).toBe(200);
  });
});

describe('verifying the challenge', () => {
  it('sets _cch, redirects back, and ships st 200 + ch 1', async () => {
    const { a, engine, app } = await v4App();
    const r = await pass(app);
    expect(r.status).toBe(302);
    expect(r.headers.get('location')).toBe('/cart');
    expect(r.headers.get('set-cookie')).toContain(`${CHALLENGE_COOKIE}=`);
    expect(r.headers.get('set-cookie')).toContain('HttpOnly');
    expect(r.headers.get('set-cookie')).toContain('SameSite=Lax');
    await engine.queue!.flush();
    expect(events(a).at(-1)).toMatchObject({ st: 200, ch: 1, tap: 'sdk-node' });
  });

  it('lets the holder of a valid _cch through', async () => {
    const { app } = await v4App();
    const cookie = (await pass(app)).headers.get('set-cookie')!.split(';')[0];
    const r = await fetch(`${app.url}/cart`, { headers: { ...html, cookie, 'x-forwarded-for': CHALLENGED_IP } });
    expect(r.status).toBe(200);
    expect(await r.text()).toContain('app');
  });

  it('does not accept a cookie minted for another ip', async () => {
    const { app } = await v4App();
    const cookie = (await pass(app)).headers.get('set-cookie')!.split(';')[0];
    const r = await fetch(`${app.url}/checkout`, { headers: { ...html, cookie, 'x-forwarded-for': '203.0.114.55' } });
    expect(r.status).toBe(403);
  });

  it('re-serves the page on a wrong solution and sets no cookie', async () => {
    const { app } = await v4App();
    const page = await fetch(`${app.url}/cart`, { headers: { ...html, 'x-forwarded-for': CHALLENGED_IP } });
    const nonce = nonceOf(await page.text());
    const r = await verify(app, `nonce=${nonce}&solution=1&to=%2Fcart`);
    expect(r.status).toBe(403);
    expect(await r.text()).toContain('Checking your browser');
    expect(r.headers.get('set-cookie')).toBeNull();
  });

  it('rejects a forged nonce even with a valid proof of work', async () => {
    const { app } = await v4App();
    const forged = 'a'.repeat(32);
    const r = await verify(app, `nonce=${forged}&solution=${solve(forged)}&to=%2Fcart`);
    expect(r.status).toBe(403);
    expect(r.headers.get('set-cookie')).toBeNull();
  });

  it('never redirects off-site', async () => {
    const { app } = await v4App();
    const page = await fetch(`${app.url}/cart`, { headers: { ...html, 'x-forwarded-for': CHALLENGED_IP } });
    const nonce = nonceOf(await page.text());
    const r = await verify(app, `nonce=${nonce}&solution=${solve(nonce)}&to=${encodeURIComponent('https://evil.test')}`);
    expect(r.headers.get('location')).toBe('/');
  });

  it('still blocks a blocked ip at the verify endpoint', async () => {
    const { app } = await v4App();
    const r = await verify(app, 'nonce=x&solution=1&to=%2F', { 'x-forwarded-for': BLOCKED_IP });
    expect(r.status).toBe(403);
    expect(r.headers.get('x-block-reason')).toBe('ip4');
  });
});

describe('serveChallenge()', () => {
  it('gates a route on demand and steps aside once passed', async () => {
    const a = fakeAnalyst();
    a.v4 = true;
    const engine = engineWith(a, { CAMADA_TRUSTED_PROXY: 'hops:1' });
    await loaded(engine);
    const app = await serve((req, res) => {
      if (engine.handle(req, res)) return;
      if (req.url?.startsWith('/challenge-me') && engine.serveChallenge(req, res)) return;
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<html><body>passed</body></html>');
    });
    open.push(app, engine);

    const first = await fetch(`${app.url}/challenge-me`, { headers: { ...html, 'x-forwarded-for': '8.8.8.8' } });
    expect(first.status).toBe(403);
    const nonce = nonceOf(await first.text());
    const ok = await fetch(`${app.url}/__camada/challenge`, {
      method: 'POST', redirect: 'manual',
      headers: { 'x-forwarded-for': '8.8.8.8', 'content-type': 'application/x-www-form-urlencoded' },
      body: `nonce=${nonce}&solution=${solve(nonce)}&to=%2Fchallenge-me`,
    });
    const cookie = ok.headers.get('set-cookie')!.split(';')[0];
    const second = await fetch(`${app.url}/challenge-me`, { headers: { ...html, cookie, 'x-forwarded-for': '8.8.8.8' } });
    expect(second.status).toBe(200);
    expect(await second.text()).toContain('passed');
    await settle();
  });

  it('ships exactly one event for the request it answers', async () => {
    const a = fakeAnalyst();
    a.v4 = true;
    const engine = engineWith(a, { CAMADA_TRUSTED_PROXY: 'hops:1' });
    await loaded(engine);
    const app = await serve((req, res) => {
      if (engine.handle(req, res)) return;
      if (engine.serveChallenge(req, res)) return;
      res.writeHead(200).end('passed');
    });
    open.push(app, engine);
    a.events.length = 0;

    await fetch(`${app.url}/challenge-me`, { headers: { ...html, 'x-forwarded-for': '8.8.8.8' } });
    await settle();
    await engine.queue!.flush();
    // The response-finish hook must not add a second, reason-less row for the same request.
    expect(events(a).filter((e) => e.p === '/challenge-me')).toHaveLength(1);
    expect(events(a).at(-1)).toMatchObject({ st: 403, blk: 'challenge' });
  });
});
