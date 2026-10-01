import { describe, it, expect, afterEach } from 'vitest';
import { connect } from 'node:net';
import { version } from '../package.json';
import type { Camada } from '../src/index.js';
import iife from '@camada/browser/iife-string';
import { fakeAnalyst, engineWith, loaded, serve, settle, BLOCKED_IP, type App } from './harness.js';

const open: Array<App | Camada> = [];
afterEach(async () => { for (const o of open.splice(0)) { 'close' in o ? await o.close() : o.stop(); } });

async function appWith(engine: Camada) {
  const app = await serve((req, res) => {
    if (engine.handle(req, res)) return;
    if (req.url === '/slow') { res.writeHead(200); res.write('a'); setTimeout(() => res.end('b'), 150); return; }
    if (req.url?.startsWith('/api/')) { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"ok":true}'); return; }
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(`<html><head>${engine.scriptTag(req)}</head><body>hi</body></html>`);
  });
  open.push(app, engine);
  return app;
}

describe('inline blocking', () => {
  it('answers 403 before the app and still ships the event', async () => {
    const a = fakeAnalyst();
    const engine = engineWith(a, { CAMADA_TRUSTED_PROXY: 'hops:1' });
    await loaded(engine);
    const app = await appWith(engine);
    const r = await fetch(`${app.url}/`, { headers: { 'x-forwarded-for': BLOCKED_IP } });
    expect(r.status).toBe(403);
    expect(r.headers.get('x-block-reason')).toBe('ip4');
    expect(r.headers.get('x-block-version')).toBeTruthy();
    await engine.queue!.flush();
    const evs = a.events.flat() as Array<Record<string, unknown>>;
    expect(evs).toHaveLength(1);
    expect(evs[0].st).toBe(403);
    expect(evs[0].blk).toBe('ip4');
    expect(evs[0].ip).toBe(BLOCKED_IP);
    expect(evs[0].tap).toBe('sdk-node');
  });

  it('ignores a spoofed XFF without trusted-proxy config', async () => {
    const a = fakeAnalyst();
    const engine = engineWith(a);
    await loaded(engine);
    const app = await appWith(engine);
    const r = await fetch(`${app.url}/`, { headers: { 'x-forwarded-for': BLOCKED_IP } });
    expect(r.status).toBe(200);
  });

  it('fails open while the snapshot server is down (cold)', async () => {
    const a = fakeAnalyst();
    a.snapshotDown = true;
    const engine = engineWith(a, { CAMADA_TRUSTED_PROXY: 'hops:1' });
    const app = await appWith(engine);
    await settle();
    const r = await fetch(`${app.url}/`, { headers: { 'x-forwarded-for': BLOCKED_IP } });
    expect(r.status).toBe(200);
  });
});

describe('sdk identity', () => {
  it('sends x-camada-sdk = @camada/node/<package version> on snapshot polls and event batches', async () => {
    const a = fakeAnalyst();
    const engine = engineWith(a);
    await loaded(engine);
    const app = await appWith(engine);
    await fetch(`${app.url}/`);
    await engine.queue!.flush();
    expect(new Set(a.sdkHeaders)).toEqual(new Set([`@camada/node/${version}`]));
    expect(a.sdkHeaders.length).toBeGreaterThanOrEqual(2);   // ≥1 poll + 1 batch
  });
});

describe('request capture', () => {
  it('stamps ts at the request start, so [ts, ts + dur] is when the request ran', async () => {
    const a = fakeAnalyst();
    const engine = engineWith(a);
    await loaded(engine);
    const app = await appWith(engine);
    const t = Date.now();
    await (await fetch(`${app.url}/slow`)).text();
    await settle();
    await engine.queue!.flush();
    const ev = (a.events.flat() as Array<Record<string, unknown>>).find((e) => e.p === '/slow')!;
    expect(ev.ts as number).toBeGreaterThanOrEqual(t);
    expect(ev.ts as number).toBeLessThanOrEqual(t + 50);   // the start, not the finish ~150 ms later
    expect(ev.dur as number).toBeGreaterThanOrEqual(140);
  });

  it('captures on response-finish: real status, latency, wire header order, session', async () => {
    const a = fakeAnalyst();
    const engine = engineWith(a);
    await loaded(engine);
    const app = await appWith(engine);
    const r1 = await fetch(`${app.url}/pricing?ref=x`, { headers: { 'User-Agent': 'test-ua', Accept: 'text/html' } });
    expect(r1.status).toBe(200);
    expect(r1.headers.get('x-rid')).toMatch(/[0-9a-f-]{36}/);
    const cookie = r1.headers.get('set-cookie');
    expect(cookie).toContain('_sfp=');
    await settle();
    await engine.queue!.flush();
    const ev = (a.events.flat() as Array<Record<string, unknown>>)[0];
    expect(ev.st).toBe(200);
    expect(ev.blk).toBeUndefined();
    expect(typeof ev.dur).toBe('number');
    expect(ev.p).toBe('/pricing');
    expect(ev.q).toBe('?ref=x');
    expect(ev.ns).toBe(1);
    expect(String(ev.hord)).toContain('user-agent');
    expect(ev.proto).toBe('HTTP/1.1');
    // second request with the cookie: same sid, not a new session
    const sid = /_sfp=([^;]+)/.exec(cookie!)![1];
    await fetch(`${app.url}/`, { headers: { cookie: `_sfp=${sid}` } });
    await settle();
    await engine.queue!.flush();
    const ev2 = (a.events.flat() as Array<Record<string, unknown>>)[1];
    expect(ev2.sid).toBe(sid);
    expect(ev2.ns).toBe(0);
  });

  it('honors exclude and never captures credentials', async () => {
    const a = fakeAnalyst();
    a.config.exclude = ['/static/'];
    const engine = engineWith(a);
    await loaded(engine);
    const app = await appWith(engine);
    await fetch(`${app.url}/static/app.css`);
    await fetch(`${app.url}/login?token=tok-live-secret123456789012345678`, { headers: { authorization: 'Bearer super.secret.jwt' } });
    await settle();
    await engine.queue!.flush();
    const evs = a.events.flat() as Array<Record<string, unknown>>;
    expect(evs).toHaveLength(1);   // /static/ excluded
    const wire = JSON.stringify(evs);
    expect(wire).not.toContain('super.secret.jwt');
    expect(wire).not.toContain('tok-live-secret123456789012345678');
    expect(evs[0].auth).toBe('Bearer');
  });

  it('track() ships an app-context event with a hashed uid', async () => {
    const a = fakeAnalyst();
    const engine = engineWith(a);
    await loaded(engine);
    const app = await serve((req, res) => {
      engine.handle(req, res);
      engine.track(req, 'login_failed', { user: 'alice@example.com' });
      res.writeHead(401); res.end();
    });
    open.push(app, engine);
    await fetch(`${app.url}/login`, { method: 'POST' });
    await settle();
    await engine.queue!.flush();
    const evs = a.events.flat() as Array<Record<string, unknown>>;
    const track = evs.find((e) => e.et === 'login_failed')!;
    expect(track.uid).toMatch(/^[0-9a-f]{32}$/);
    expect(JSON.stringify(evs)).not.toContain('alice');
  });
});

describe('client abort', () => {
  // A stream the client drops: Node emits 'close' and never 'finish'.
  async function sseApp(engine: Camada) {
    const app = await serve((req, res) => {
      if (engine.handle(req, res)) return;
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      let n = 0;
      const t = setInterval(() => { res.write(`data: ${n}\n\n`); if (++n === 8) { clearInterval(t); res.end(); } }, 50);
      res.on('close', () => clearInterval(t));
    });
    open.push(app, engine);
    return app;
  }

  it('ships exactly one event when the client aborts mid-stream, timed to the abort', async () => {
    const a = fakeAnalyst();
    const engine = engineWith(a);
    await loaded(engine);
    const app = await sseApp(engine);
    const ac = new AbortController();
    const r = await fetch(`${app.url}/sse`, { signal: ac.signal });
    const reader = r.body!.getReader();
    await reader.read();
    await settle(120);
    ac.abort();
    await settle(50);
    await engine.queue!.flush();
    const evs = (a.events.flat() as Array<Record<string, unknown>>).filter((e) => e.p === '/sse');
    expect(evs).toHaveLength(1);
    expect(evs[0].st).toBe(200);
    expect(evs[0].dur as number).toBeGreaterThanOrEqual(100);
    expect(evs[0].dur as number).toBeLessThan(350);   // the abort, not the 400 ms stream
    app.server.closeAllConnections();
  });

  it('a stream read to the end still ships exactly one event', async () => {
    const a = fakeAnalyst();
    const engine = engineWith(a);
    await loaded(engine);
    const app = await sseApp(engine);
    await (await fetch(`${app.url}/sse`)).text();
    await settle(50);
    await engine.queue!.flush();
    const evs = (a.events.flat() as Array<Record<string, unknown>>).filter((e) => e.p === '/sse');
    expect(evs).toHaveLength(1);
    expect(evs[0].dur as number).toBeGreaterThanOrEqual(350);
  });
});

describe('first-party beacon', () => {
  it('serves the IIFE at /_cam/b.js and batches /_cam/fp into the event queue as a sig:1 row with the resolved client IP', async () => {
    const a = fakeAnalyst();
    const engine = engineWith(a, { CAMADA_TRUSTED_PROXY: 'hops:1' });
    await loaded(engine);
    const app = await appWith(engine);
    const js = await fetch(`${app.url}/_cam/b.js?r=abc`);
    expect(js.status).toBe(200);
    expect(js.headers.get('content-type')).toContain('javascript');
    expect(await js.text()).toBe(iife);
    const fp = await fetch(`${app.url}/_cam/fp`, { method: 'POST', body: JSON.stringify({ rid: 'abc', tz: 'UTC' }), headers: { 'x-forwarded-for': '9.9.9.9' } });
    expect(fp.status).toBe(204);
    await settle();
    await engine.queue!.flush();
    expect(a.beacons).toHaveLength(0);   // no per-page-view POST: one request and one R2 put per flush at the analyst, not per beacon
    const rows = a.events.flat() as Array<Record<string, unknown>>;
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ sig: 1, rid: 'abc', tz: 'UTC', ip: '9.9.9.9', tap: 'sdk-node' });
  });

  it('drops an unparseable beacon body instead of shipping it', async () => {
    const a = fakeAnalyst();
    const engine = engineWith(a);
    await loaded(engine);
    const app = await appWith(engine);
    const fp = await fetch(`${app.url}/_cam/fp`, { method: 'POST', body: 'not-json' });
    expect(fp.status).toBe(204);
    await settle();
    await engine.queue!.flush();
    expect(a.events.flat()).toHaveLength(0);
    expect(a.beacons).toHaveLength(0);
  });

  it('rejects oversized beacon posts', async () => {
    const a = fakeAnalyst();
    const engine = engineWith(a);
    await loaded(engine);
    const app = await appWith(engine);
    const fp = await fetch(`${app.url}/_cam/fp`, { method: 'POST', body: 'x'.repeat(80 * 1024) });
    expect(fp.status).toBe(413);
    expect(a.beacons).toHaveLength(0);
  });

  it('serves nothing when the tenant disabled the beacon', async () => {
    const a = fakeAnalyst();
    a.config.beacon = false;
    const engine = engineWith(a);
    await loaded(engine);
    const app = await appWith(engine);
    const js = await fetch(`${app.url}/_cam/b.js`);
    expect(js.status).toBe(200);                       // fell through to the app (html)
    expect(js.headers.get('content-type')).toContain('html');
    expect(engine.scriptTag({ } as never)).toBe('');
  });
});

describe('fail-open envelope', () => {
  it('the app keeps serving when ingest is down', async () => {
    const a = fakeAnalyst();
    a.ingestDown = true;
    const engine = engineWith(a);
    await loaded(engine);
    const app = await appWith(engine);
    for (let i = 0; i < 5; i++) expect((await fetch(`${app.url}/api/data`)).status).toBe(200);
    await engine.queue!.flush();   // must not throw
  });

  it('CAMADA_DISABLED=1 bypasses the SDK entirely', async () => {
    const a = fakeAnalyst();
    const engine = engineWith(a, { CAMADA_DISABLED: '1', CAMADA_TRUSTED_PROXY: 'hops:1' });
    const app = await appWith(engine);
    const r = await fetch(`${app.url}/`, { headers: { 'x-forwarded-for': BLOCKED_IP } });
    expect(r.status).toBe(200);
    expect(r.headers.get('x-rid')).toBeNull();
    expect(engine.scriptTag({} as never)).toBe('');
  });

  it('stays inert without credentials instead of crashing the app', async () => {
    const a = fakeAnalyst();
    const engine = engineWith(a, { CAMADA_KEY: undefined as unknown as string });
    const app = await appWith(engine);
    expect((await fetch(`${app.url}/`)).status).toBe(200);
  });
});

/** A raw WebSocket-style handshake: sends the upgrade request, then `hi` once the 101 is in; resolves with all it read. */
function handshake(port: number, path: string, headers: Record<string, string> = {}): Promise<string> {
  return new Promise((resolve, reject) => {
    const sock = connect(port, '127.0.0.1', () => {
      const extra = Object.entries(headers).map(([k, v]) => `${k}: ${v}\r\n`).join('');
      sock.write(`GET ${path} HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n${extra}\r\n`);
    });
    let got = '';
    sock.on('data', (d) => {
      got += d;
      if (got.includes('\r\n\r\n') && !got.includes('echo:') && got.startsWith('HTTP/1.1 101')) sock.write('hi');
      if (got.includes('echo:hi') || (got.includes('\r\n\r\n') && !got.startsWith('HTTP/1.1 101'))) sock.end();
    });
    sock.on('close', () => resolve(got));
    sock.on('error', reject);
  });
}

describe('WebSocket upgrades (attach)', () => {
  async function wsApp(engine: Camada, listener = true) {
    const app = await appWith(engine);
    if (listener) {
      app.server.on('upgrade', (_req, socket) => {   // what ws does: answer 101 itself, then speak the protocol
        socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n');
        socket.on('data', (d: Buffer) => socket.end(`echo:${d}`));
      });
    }
    return app;
  }
  const shipped = async (a: ReturnType<typeof fakeAnalyst>, engine: Camada) => {
    await settle();
    await engine.queue!.flush();
    return a.events.flat() as Array<Record<string, unknown>>;
  };

  it('ships exactly one st 101 event per upgrade and leaves the handshake to the app', async () => {
    const a = fakeAnalyst();
    const engine = engineWith(a);
    await loaded(engine);
    const app = await wsApp(engine);
    expect(engine.attach(engine.attach(app.server))).toBe(app.server);   // idempotent
    const got = await handshake(app.port, '/ws?room=1', { cookie: '_sfp=known-sid' });
    expect(got).toMatch(/^HTTP\/1\.1 101 Switching Protocols\r\n/);
    expect(got).not.toContain('set-cookie');
    expect(got.endsWith('echo:hi')).toBe(true);
    const evs = await shipped(a, engine);
    expect(evs).toHaveLength(1);
    expect(evs[0]).toMatchObject({ st: 101, p: '/ws', q: '?room=1', sid: 'known-sid' });
    expect(typeof evs[0].ts).toBe('number');
    expect(typeof evs[0].dur).toBe('number');
  });

  it('leaves a server with no upgrade listener of its own exactly as it was', async () => {
    // Node routes an upgrade request to the request handler when nothing listens for 'upgrade'; a
    // listener of camada's would have claimed it and left the client hanging.
    const a = fakeAnalyst();
    const engine = engineWith(a);
    await loaded(engine);
    const app = await wsApp(engine, false);
    engine.attach(app.server);
    expect(app.server.listenerCount('upgrade')).toBe(0);
    expect(await handshake(app.port, '/plain')).toMatch(/^HTTP\/1\.1 200 OK/);
    expect((await shipped(a, engine)).map((e) => [e.p, e.st])).toEqual([['/plain', 200]]);
  });

  it('ships nothing for an excluded path and is inert when camada is', async () => {
    const a = fakeAnalyst();
    a.config = { ...a.config, exclude: ['/ws'] };
    const engine = engineWith(a);
    await loaded(engine);
    const app = await wsApp(engine);
    engine.attach(app.server);
    expect((await handshake(app.port, '/ws')).endsWith('echo:hi')).toBe(true);
    expect(await shipped(a, engine)).toHaveLength(0);

    const off = engineWith(fakeAnalyst(), { CAMADA_DISABLED: '1' });
    open.push(off);
    const emit = app.server.emit;
    expect(off.attach(app.server)).toBe(app.server);
    expect(app.server.emit).toBe(emit);
  });
});
