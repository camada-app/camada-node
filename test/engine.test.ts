import { describe, it, expect, afterEach } from 'vitest';
import type { Camada } from '../src/index.js';
import iife from '@camada/browser/iife-string';
import { fakeAnalyst, engineWith, loaded, serve, settle, BLOCKED_IP, type App } from './harness.js';

const open: Array<App | Camada> = [];
afterEach(async () => { for (const o of open.splice(0)) { 'close' in o ? await o.close() : o.stop(); } });

async function appWith(engine: Camada) {
  const app = await serve((req, res) => {
    if (engine.handle(req, res)) return;
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

describe('request capture', () => {
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

describe('first-party beacon', () => {
  it('serves the IIFE at /_cam/b.js and relays /_cam/fp with the resolved client IP', async () => {
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
    expect(a.beacons).toHaveLength(1);
    expect(a.beacons[0].clientIp).toBe('9.9.9.9');
    expect(JSON.parse(a.beacons[0].body).tap).toBe('sdk-node');
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
