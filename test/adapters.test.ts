// One smoke test per adapter: blocked IP -> 403 before the app; normal request -> app response
// with x-rid. Real framework instances, real sockets.
import { describe, it, expect, afterEach } from 'vitest';
import { createHash } from 'node:crypto';
import type { Server } from 'node:http';
import { connect } from 'node:net';
import { get as httpGet } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CHALLENGE_COOKIE } from '@camada/core';
import { fakeAnalyst, engineWith, loaded, settle, BLOCKED_IP, CHALLENGED_IP, type FakeAnalyst } from './harness.js';
import { camadaFastify } from '../src/fastify.js';
import { camadaKoa } from '../src/koa.js';

const closers: Array<() => Promise<unknown> | unknown> = [];
afterEach(async () => { for (const c of closers.splice(0)) await c(); });

async function ready(v4 = false) {
  const a = fakeAnalyst();
  a.v4 = v4;   // v4-basic: block /blocked-path + /locked/, challenge /admin/ and CHALLENGED_IP
  const engine = engineWith(a, { CAMADA_TRUSTED_PROXY: 'hops:1' });
  closers.push(() => engine.stop());
  await loaded(engine);
  return { a, engine };
}

const hit = async (port: number, blocked = false) =>
  fetch(`http://127.0.0.1:${port}/`, blocked ? { headers: { 'x-forwarded-for': BLOCKED_IP } } : undefined);

describe('adapters', () => {
  it('express', async () => {
    const { engine } = await ready();
    const { default: express } = await import('express');
    const app = express();
    app.use(engine.express());
    app.get('/', (_req, res) => { res.send('ok'); });
    const server = await new Promise<import('node:http').Server>((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
    closers.push(() => new Promise((r) => server.close(r)));
    const port = (server.address() as { port: number }).port;
    expect((await hit(port, true)).status).toBe(403);
    const ok = await hit(port);
    expect(ok.status).toBe(200);
    expect(ok.headers.get('x-rid')).toBeTruthy();
  });

  it('fastify', async () => {
    const { engine } = await ready();
    const { default: Fastify } = await import('fastify');
    const app = Fastify();
    await app.register(camadaFastify as never, { camada: engine } as never);
    app.get('/', async () => 'ok');
    await app.listen({ port: 0, host: '127.0.0.1' });
    closers.push(() => app.close());
    const port = (app.server.address() as { port: number }).port;
    expect((await hit(port, true)).status).toBe(403);
    const ok = await hit(port);
    expect(ok.status).toBe(200);
    expect(ok.headers.get('x-rid')).toBeTruthy();
  });

  it('koa', async () => {
    const { engine } = await ready();
    const { default: Koa } = await import('koa');
    const app = new Koa();
    app.use(camadaKoa(engine));
    app.use(async (ctx) => { ctx.body = 'ok'; });
    const server = await new Promise<import('node:http').Server>((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
    closers.push(() => new Promise((r) => server.close(r)));
    const port = (server.address() as { port: number }).port;
    expect((await hit(port, true)).status).toBe(403);
    const ok = await hit(port);
    expect(ok.status).toBe(200);
    expect(ok.headers.get('x-rid')).toBeTruthy();
  });

  it('nest (express platform)', async () => {
    const { engine } = await ready();
    await import('reflect-metadata');
    const { CamadaModule } = await import('../src/nest.js');
    const { Module, Controller, Get } = await import('@nestjs/common');
    const { NestFactory } = await import('@nestjs/core');

    @Controller()
    class RootController {
      @Get() root() { return 'ok'; }
    }
    @Module({ imports: [CamadaModule.forRoot({ camada: engine })], controllers: [RootController] })
    class AppModule {}

    const app = await NestFactory.create(AppModule, { logger: false });
    await app.listen(0, '127.0.0.1');
    closers.push(() => app.close());
    const port = (app.getHttpServer().address() as { port: number }).port;
    expect((await hit(port, true)).status).toBe(403);
    const ok = await hit(port);
    expect(ok.status).toBe(200);
    expect(ok.headers.get('x-rid')).toBeTruthy();
  });
});

// ---- the request's real path, whatever the mount (camada-all-6ogs) and an already-read body
// (camada-all-r3s6). Every app below answers 200 'app' only when camada let the request through.

const html = { accept: 'text/html', 'sec-fetch-dest': 'document' };
const nonceOf = (page: string) => /name="nonce" value="([0-9a-f]{32})"/.exec(page)![1];
const solve = (nonce: string): string => {
  for (let n = 0; ; n++) if (createHash('sha256').update(`${nonce}.${n}`).digest('hex').startsWith('0000')) return String(n);
};
const actionOf = (page: string) => /<form id="camada-f" method="POST" action="([^"]*)"/.exec(page)![1];
const rows = async (a: FakeAnalyst, engine: { queue: { flush(): Promise<void> } | null }) => {
  await settle();
  await engine.queue!.flush();
  return a.events.flat() as Array<Record<string, unknown>>;
};
const portOf = (s: Server) => (s.address() as { port: number }).port;
const listen = (app: { listen: (p: number, h: string, cb: () => void) => Server }) =>
  new Promise<Server>((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });

/** Path block, path challenge, the beacon script, and the shipped `p`/`q` through `base`. */
async function expectRealPaths(base: string, a: FakeAnalyst, engine: { queue: { flush(): Promise<void> } | null }, prefix = '') {
  const blocked = await fetch(`${base}${prefix}/blocked-path`);
  expect(blocked.status).toBe(prefix ? 200 : 403);   // under a prefix the real path is /api/blocked-path: no rule
  if (!prefix) expect(blocked.headers.get('x-block-reason')).toBe('path');
  if (!prefix) {
    const locked = await fetch(`${base}/locked/secret`);
    expect(locked.status).toBe(403);
    expect(locked.headers.get('x-block-reason')).toBe('path');
    const ch = await fetch(`${base}/admin/users`, { headers: html });
    expect(ch.status).toBe(403);
    expect(ch.headers.get('x-camada-challenge')).toBe('1');
    const api = await fetch(`${base}/admin/users`, { headers: { accept: 'application/json' } });   // 82ar: not a page, passes flagged
    expect(api.status).toBe(200);
    expect(api.headers.get('x-camada-challenge')).toBe('1');
    const js = await fetch(`${base}/_cam/b.js`);
    expect(js.status).toBe(200);
    expect(js.headers.get('content-type')).toContain('javascript');
  }
  a.events.length = 0;
  const ok = await fetch(`${base}${prefix}/shop/item?id=7`);
  expect(ok.status).toBe(200);
  expect(await ok.text()).toBe('app');
  const evs = await rows(a, engine);
  expect(evs).toContainEqual(expect.objectContaining({ p: `${prefix}/shop/item`, q: '?id=7', st: 200 }));
  expect(evs.filter((e) => e.st && e.p === '/')).toHaveLength(0);   // nothing stripped to the mount
}

/** Solves a served challenge (correct -> 302 + _cch, wrong -> 403 page) and posts a beacon (204 + sig:1 row). */
async function expectBodyEndpoints(base: string, a: FakeAnalyst, engine: { queue: { flush(): Promise<void> } | null }, prefix = '') {
  const xff = { 'x-forwarded-for': CHALLENGED_IP };
  const page = await fetch(`${base}${prefix}/cart`, { headers: { ...html, ...xff } });
  expect(page.status).toBe(403);
  const body = await page.text();
  const nonce = nonceOf(body);
  const action = actionOf(body);
  expect(action).toBe(`${prefix}/__camada/challenge`);   // R2-4: the form posts where camada answers
  const post = (body: string) => fetch(`${base}${action}`, {
    method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(2000),
    headers: { ...xff, 'content-type': 'application/x-www-form-urlencoded' }, body,
  });
  const wrong = await post(`nonce=${nonce}&solution=nope&to=%2Fcart`);
  expect(wrong.status).toBe(403);
  expect(wrong.headers.get('set-cookie')).toBeNull();
  const right = await post(`nonce=${nonce}&solution=${solve(nonce)}&to=%2Fcart`);
  expect(right.status).toBe(302);
  expect(right.headers.get('location')).toBe('/cart');
  expect(right.headers.get('set-cookie')).toContain(`${CHALLENGE_COOKIE}=`);
  a.events.length = 0;
  const fp = await fetch(`${base}${prefix}/_cam/fp`, {
    method: 'POST', signal: AbortSignal.timeout(2000),
    headers: { 'content-type': 'application/json', 'x-forwarded-for': '9.9.9.9' },
    body: JSON.stringify({ rid: 'abc', tz: 'UTC' }),
  });
  expect(fp.status).toBe(204);
  expect(await rows(a, engine)).toContainEqual(expect.objectContaining({ sig: 1, rid: 'abc', tz: 'UTC', ip: '9.9.9.9' }));
}

/** The beacon tag rendered by the app points under the mount, and that URL serves the script (R2-4). */
async function expectScriptTag(base: string, prefix: string) {
  const tag = await (await fetch(`${base}${prefix}/page`, { headers: { 'x-tag': '1' } })).text();
  const src = /<script src="([^"?]*)/.exec(tag)![1];
  expect(src).toBe(`${prefix}/_cam/b.js`);
  const js = await fetch(`${base}${src}`);
  expect(js.status).toBe(200);
  expect(js.headers.get('content-type')).toContain('javascript');
}

/** camada's own endpoints answer under a prefix mount at `${prefix}/…` (R1-19). */
async function expectOwnEndpoints(base: string, prefix: string) {
  const js = await fetch(`${base}${prefix}/_cam/b.js`);
  expect(js.status).toBe(200);
  expect(js.headers.get('content-type')).toContain('javascript');
  const fp = await fetch(`${base}${prefix}/_cam/fp`, { method: 'POST', signal: AbortSignal.timeout(2000), body: '{"rid":"x"}' });
  expect(fp.status).toBe(204);
}

async function nestApp(engine: ReturnType<typeof engineWith>) {
  await import('reflect-metadata');
  const { CamadaModule } = await import('../src/nest.js');
  const { Module, Controller, All } = await import('@nestjs/common');
  const { NestFactory } = await import('@nestjs/core');
  @Controller()
  class AnyController {
    @All('{*p}') any() { return 'app'; }
  }
  @Module({ imports: [CamadaModule.forRoot({ camada: engine })], controllers: [AnyController] })
  class AppModule {}
  const app = await NestFactory.create(AppModule, { logger: false });   // default platform: json + urlencoded parsers run first
  await app.listen(0, '127.0.0.1');
  closers.push(() => app.close());
  return `http://127.0.0.1:${portOf(app.getHttpServer())}`;
}

describe('nest 11 (default platform, README mount)', () => {
  it('enforces path rules, serves the beacon, and ships the real path and query', async () => {
    const { a, engine } = await ready(true);
    await expectRealPaths(await nestApp(engine), a, engine);
  });

  it('answers the challenge verify and beacon POSTs behind Nest\'s own body parsers', async () => {
    const { a, engine } = await ready(true);
    await expectBodyEndpoints(await nestApp(engine), a, engine);
  });
});

describe('express mounts', () => {
  async function expressApp(mount: (app: import('express').Express, mw: ReturnType<ReturnType<typeof engineWith>['express']>) => void, engine: ReturnType<typeof engineWith>) {
    const { default: express } = await import('express');
    const app = express();
    mount(app, engine.express());
    app.use((req, res) => { res.send(req.headers['x-tag'] ? engine.scriptTag(req) : 'app'); });
    const server = await listen(app);
    closers.push(() => new Promise((r) => server.close(r)));
    return `http://127.0.0.1:${portOf(server)}`;
  }

  it('a prefix mount ships the full path', async () => {
    const { a, engine } = await ready(true);
    await expectRealPaths(await expressApp((app, mw) => app.use('/api', mw), engine), a, engine, '/api');
  });

  it('a prefix mount still answers its own endpoints under the prefix (R1-19)', async () => {
    const { a, engine } = await ready(true);
    const base = await expressApp((app, mw) => app.use('/api', mw), engine);
    await expectOwnEndpoints(base, '/api');
    await expectBodyEndpoints(base, a, engine, '/api');
    await expectScriptTag(base, '/api');
  });

  it('explicit scriptPath / challengePath are used as configured under a prefix mount (R2-4)', async () => {
    const a = fakeAnalyst();
    a.v4 = true;
    const engine = engineWith(a, { CAMADA_TRUSTED_PROXY: 'hops:1' }, { scriptPath: '/api/x/b.js', challengePath: '/api/x/ch' });
    closers.push(() => engine.stop());
    await loaded(engine);
    const base = await expressApp((app, mw) => app.use('/api', mw), engine);
    const page = await fetch(`${base}/api/cart`, { headers: { ...html, 'x-forwarded-for': CHALLENGED_IP } });
    expect(actionOf(await page.text())).toBe('/api/x/ch');
    const tag = await (await fetch(`${base}/api/page`, { headers: { 'x-tag': '1' } })).text();
    expect(tag).toContain('src="/api/x/b.js?r=');
  });

  it("a wildcard mount (what Nest <= 10 registers for routes: '*') still sees the real path", async () => {
    const { a, engine } = await ready(true);
    await expectRealPaths(await expressApp((app, mw) => app.use('*', mw), engine), a, engine);
  });

  it('json + urlencoded parsers mounted first: verify and beacon still answer', async () => {
    const { a, engine } = await ready(true);
    const { default: express } = await import('express');
    await expectBodyEndpoints(await expressApp((app, mw) => { app.use(express.json(), express.urlencoded({ extended: false }), mw); }, engine), a, engine);
  });

  it('express.raw({ type: "*/*" }) first: a Buffer body still verifies and relays (R1-16)', async () => {
    const { a, engine } = await ready(true);
    const { default: express } = await import('express');
    await expectBodyEndpoints(await expressApp((app, mw) => { app.use(express.raw({ type: '*/*' }), mw); }, engine), a, engine);
  });

  it('express.text({ type: "*/*" }) first: a string body still verifies and relays (R1-16)', async () => {
    const { a, engine } = await ready(true);
    const { default: express } = await import('express');
    await expectBodyEndpoints(await expressApp((app, mw) => { app.use(express.text({ type: '*/*' }), mw); }, engine), a, engine);
  });

  it('an oversized body a parser already drained: verify re-serves the page, the beacon is 413 (R1-16)', async () => {
    const { a, engine } = await ready(true);
    const { default: express } = await import('express');
    const base = await expressApp((app, mw) => { app.use(express.text({ type: '*/*', limit: '1mb' }), mw); }, engine);
    const big = 'x'.repeat(40 * 1024);
    const ch = await fetch(`${base}/__camada/challenge`, {
      method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(2000),
      headers: { 'x-forwarded-for': CHALLENGED_IP }, body: `nonce=x&solution=1&to=%2F&pad=${big}`,
    });
    expect(ch.status).toBe(403);
    expect(ch.headers.get('x-camada-challenge')).toBe('1');
    expect(ch.headers.get('set-cookie')).toBeNull();
    a.events.length = 0;
    const fp = await fetch(`${base}/_cam/fp`, { method: 'POST', signal: AbortSignal.timeout(2000), body: JSON.stringify({ rid: 'big', pad: big }) });
    expect(fp.status).toBe(413);
    expect((await rows(a, engine)).filter((e) => e.sig)).toHaveLength(0);
  });

  it('object bodies with array values: verify ignores non-string fields, the beacon keeps them (R1-16)', async () => {
    const { a, engine } = await ready(true);
    const { default: express } = await import('express');
    const base = await expressApp((app, mw) => { app.use(express.json(), express.urlencoded({ extended: true }), mw); }, engine);
    const page = await fetch(`${base}/cart`, { headers: { ...html, 'x-forwarded-for': CHALLENGED_IP } });
    const nonce = nonceOf(await page.text());
    const ch = await fetch(`${base}/__camada/challenge`, {
      method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(2000),
      headers: { 'x-forwarded-for': CHALLENGED_IP, 'content-type': 'application/x-www-form-urlencoded' },
      body: `nonce=${nonce}&solution=${solve(nonce)}&solution=1&to=%2Fcart`,   // repeated -> an array
    });
    expect(ch.status).toBe(403);
    expect(ch.headers.get('set-cookie')).toBeNull();
    a.events.length = 0;
    const post = (body: string) => fetch(`${base}/_cam/fp`, {
      method: 'POST', signal: AbortSignal.timeout(2000), headers: { 'content-type': 'application/json' }, body,
    });
    expect((await post('{"rid":"arr","langs":["en","pt"]}')).status).toBe(204);
    expect((await post('[1,2]')).status).toBe(204);   // not an object: answered, never shipped
    const sig = (await rows(a, engine)).filter((e) => e.sig);
    expect(sig).toEqual([expect.objectContaining({ rid: 'arr', langs: ['en', 'pt'] })]);
  });

  it('a body read by something that left no req.body is still answered at once', async () => {
    const { engine } = await ready(true);
    const drain = (req: import('express').Request, _res: unknown, next: () => void) => { req.resume(); req.on('end', next); };
    const base = await expressApp((app, mw) => { app.use(drain, mw); }, engine);
    const ch = await fetch(`${base}/__camada/challenge`, {
      method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(2000),
      headers: { 'x-forwarded-for': CHALLENGED_IP, 'content-type': 'application/x-www-form-urlencoded' }, body: 'nonce=x&solution=1',
    });
    expect(ch.status).toBe(403);
    const fp = await fetch(`${base}/_cam/fp`, { method: 'POST', signal: AbortSignal.timeout(2000), body: '{"rid":"x"}' });
    expect(fp.status).toBe(204);
  });
});

// R1-1: a client that resets its socket before camada runs leaves no readable peer address. With
// a cidrs (Cloudflare-style) config the X-Forwarded-For walk would then believe whatever the
// client wrote: a spoofed blocked ip (victim framing) or any clean ip (block evasion).
describe('client ip with the peer already gone', () => {
  // Every mode, not only cidrs (contract C6 v3.1): hops and vercel never look at the peer, so a
  // resolve with XFF would take the client's own entry there.
  for (const mode of ['cidrs:173.245.48.0/20,103.21.244.0/22,127.0.0.0/8', 'hops:1', 'vercel']) it(`${mode.split(':')[0]}: an adapter with a socket but no readable peer resolves no ip instead of believing X-Forwarded-For`, async () => {
    const a = fakeAnalyst();
    const engine = engineWith(a, { CAMADA_TRUSTED_PROXY: mode });
    closers.push(() => engine.stop());
    await loaded(engine);
    const { default: express } = await import('express');
    const app = express();
    let peer: unknown = 'unset';
    app.use((req, _res, next) => { setTimeout(() => { peer = req.socket?.remoteAddress; next(); }, 60); });   // async middleware first
    app.use(engine.express());
    app.use((_req, res) => { res.send('app'); });
    const server = await listen(app);
    closers.push(() => new Promise((r) => server.close(r)));
    const seen: Array<string | null | undefined> = [];
    const verdict = engine.snap!.verdict.bind(engine.snap!);
    engine.snap!.verdict = (input) => { seen.push(input.ip); return verdict(input); };
    a.events.length = 0;
    await new Promise<void>((resolve) => {
      const s = connect(portOf(server), '127.0.0.1', () => {
        s.write(`POST /x HTTP/1.1\r\nHost: a\r\nX-Forwarded-For: ${BLOCKED_IP}\r\nContent-Length: 2\r\n\r\nhi`);
        setTimeout(() => { s.resetAndDestroy(); resolve(); }, 10);
      });
      s.on('error', () => {});
    });
    await settle(150);
    expect(peer).toBeUndefined();   // the precondition: node really lost the peer
    expect(seen).toEqual([null]);   // camada ran, with no ip: no ip rule can match, none can be framed
    const evs = await rows(a, engine);
    expect(evs.filter((e) => e.ip === BLOCKED_IP)).toHaveLength(0);
    expect(evs.filter((e) => e.blk)).toHaveLength(0);
  });
});

// R2-3: behind nginx/Passenger the app often listens on a unix socket, where Node never has a peer
// address. That is not the reset case above: the only hop is the local proxy, so the
// trusted-proxy walk runs without a peer (team contract C6 v3).
describe('client ip on a unix-socket listener', () => {
  it('resolves X-Forwarded-For per the trusted-proxy config', async () => {
    const a = fakeAnalyst();
    const engine = engineWith(a, { CAMADA_TRUSTED_PROXY: 'cidrs:173.245.48.0/20' });
    closers.push(() => engine.stop());
    await loaded(engine);
    const { default: express } = await import('express');
    const app = express();
    app.use(engine.express());
    app.use((_req, res) => { res.send('app'); });
    const dir = mkdtempSync(join(tmpdir(), 'cmd-'));
    const sock = join(dir, 's.sock');
    const server = await new Promise<Server>((r) => { const s = app.listen(sock, () => r(s)); });
    closers.push(() => new Promise((r) => server.close(() => { rmSync(dir, { recursive: true, force: true }); r(undefined); })));
    const get = (xff: string) => new Promise<number>((resolve, reject) => {
      httpGet({ socketPath: sock, path: '/u', headers: { 'x-forwarded-for': xff } }, (r) => { r.resume(); r.on('end', () => resolve(r.statusCode!)); }).on('error', reject);
    });
    expect(typeof server.address()).toBe('string');
    expect(await get(`${BLOCKED_IP}, 173.245.48.1`)).toBe(403);   // the walk ran: the client behind the CF hop is blocked
    a.events.length = 0;
    expect(await get('1.2.3.4, 173.245.48.1')).toBe(200);
    expect(await rows(a, engine)).toContainEqual(expect.objectContaining({ p: '/u', ip: '1.2.3.4', st: 200 }));
  });
});

describe('koa: body parser first, mounts (R1-14, R1-19)', () => {
  async function koaApp(build: (app: import('koa')) => void, engine: ReturnType<typeof engineWith>) {
    const { default: Koa } = await import('koa');
    const app = new Koa();
    build(app);
    app.use(async (ctx) => { ctx.body = ctx.get('x-tag') ? engine.scriptTag(ctx.req) : 'app'; });
    const server = await listen(app as never);
    closers.push(() => new Promise((r) => server.close(r)));
    return `http://127.0.0.1:${portOf(server)}`;
  }

  it('@koa/bodyparser before camada: verify passes (302 + _cch) and the beacon ships', async () => {
    const { a, engine } = await ready(true);
    const { bodyParser } = await import('@koa/bodyparser');
    await expectBodyEndpoints(await koaApp((app) => { app.use(bodyParser()); app.use(camadaKoa(engine)); }, engine), a, engine);
  });

  it('koa-mount: own endpoints answer under the prefix, events and path rules see the full path', async () => {
    const { a, engine } = await ready(true);
    const { default: mount } = await import('koa-mount');
    const base = await koaApp((app) => { app.use(mount('/api', camadaKoa(engine) as never)); }, engine);
    await expectOwnEndpoints(base, '/api');
    await expectRealPaths(base, a, engine, '/api');
    await expectBodyEndpoints(base, a, engine, '/api');
    await expectScriptTag(base, '/api');
  });
});
