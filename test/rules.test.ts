// Snapshot v5 (§D3): the tenant's ordered custom rules, enforced at the node tap over the
// golden v5 container edge-analyst generates. The order IS the precedence, so a skip rule that
// sits above a wider block wins — and the axes this tap really has (path, user agent and the
// request headers) must reach the matcher, or every `ua` and `header` rule silently never fires.
import { describe, it, expect, afterEach } from 'vitest';
import type { Camada } from '../src/index.js';
import {
  fakeAnalyst, engineWith, loaded, serve, settle,
  BLOCKED_IP, ALLOWED_IP, RULE_BLOCKED_IP, SKIP_PATH, RULE_BLOCKED_PATH, WARN_UA, BLOCKED_UA,
  BLOCKED_HEADER, BLOCKED_HEADER_VALUE,
  type App, type FakeAnalyst,
} from './harness.js';

const open: Array<App | Camada> = [];
afterEach(async () => { for (const o of open.splice(0)) { 'close' in o ? await o.close() : o.stop(); } });

/** A v5-serving analyst plus an app that only ever answers 200 when camada lets it through. */
async function v5App(opts: Parameters<typeof engineWith>[2] = {}) {
  const a = fakeAnalyst();
  a.v5 = true;
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

const events = (a: FakeAnalyst) => a.events.flat() as Array<Record<string, unknown>>;

/** Every event this request produced, once the response-finish hook and the queue have run. */
async function shipped(a: FakeAnalyst, engine: Camada): Promise<Array<Record<string, unknown>>> {
  await settle();
  await engine.queue!.flush();
  return events(a);
}

describe('ordered custom rules', () => {
  it('lets a skip rule beat the wider block below it', async () => {
    const { app } = await v5App();
    // The same ip is blocked on the block side; the health-check rule sits above it.
    expect((await fetch(`${app.url}${SKIP_PATH}`, { headers: { 'x-forwarded-for': BLOCKED_IP } })).status).toBe(200);
    expect((await fetch(`${app.url}/`, { headers: { 'x-forwarded-for': BLOCKED_IP } })).status).toBe(403);
  });

  it('lets the built-in Allow-list rule beat the wider block below it', async () => {
    const { a, engine, app } = await v5App();
    const r = await fetch(`${app.url}/`, { headers: { 'x-forwarded-for': ALLOWED_IP } });
    expect(r.status).toBe(200);
    const evs = await shipped(a, engine);
    expect(evs.at(-1)!.blk).toBeUndefined();   // an allowed request is an ordinary request
    expect(evs.at(-1)!.wrn).toBeUndefined();
  });

  it('blocks by rule with x-block-rule and ships blk rule + rl', async () => {
    const { a, engine, app } = await v5App();
    const r = await fetch(`${app.url}/`, { headers: { 'x-forwarded-for': RULE_BLOCKED_IP } });
    expect(r.status).toBe(403);
    expect(r.headers.get('x-block-reason')).toBe('rule');
    expect(r.headers.get('x-block-rule')).toBe('builtin:block');
    expect(r.headers.get('x-block-version')).toBeTruthy();
    const evs = await shipped(a, engine);
    expect(evs).toHaveLength(1);
    expect(evs[0]).toMatchObject({ st: 403, blk: 'rule', rl: 'builtin:block', ip: RULE_BLOCKED_IP });
  });

  it('blocks by a path rule the block side does not carry', async () => {
    const { app } = await v5App();
    const r = await fetch(`${app.url}${RULE_BLOCKED_PATH}`, { headers: { 'x-forwarded-for': '8.8.8.8' } });
    expect(r.status).toBe(403);
    expect(r.headers.get('x-block-rule')).toBe('cr_00000000000c');
  });

  it('blocks by a user-agent rule — the tap must pass ua through', async () => {
    const { a, engine, app } = await v5App();
    const r = await fetch(`${app.url}/`, { headers: { 'x-forwarded-for': '8.8.8.8', 'user-agent': BLOCKED_UA } });
    expect(r.status).toBe(403);
    expect(r.headers.get('x-block-reason')).toBe('rule');
    expect(r.headers.get('x-block-rule')).toBe('cr_00000000000f');
    expect((await shipped(a, engine))[0]).toMatchObject({ blk: 'rule', rl: 'cr_00000000000f' });
  });

  it('blocks by a header rule — the tap must pass a header getter through', async () => {
    const { a, engine, app } = await v5App();
    const r = await fetch(`${app.url}/`, {
      headers: { 'x-forwarded-for': '8.8.8.8', [BLOCKED_HEADER]: BLOCKED_HEADER_VALUE },
    });
    expect(r.status).toBe(403);
    expect(r.headers.get('x-block-reason')).toBe('rule');
    expect(r.headers.get('x-block-rule')).toBe('cr_000000000019');
    expect((await shipped(a, engine))[0]).toMatchObject({ blk: 'rule', rl: 'cr_000000000019' });
  });

  it('matches a header rule however the client spelled the name', async () => {
    const { app } = await v5App();
    const r = await fetch(`${app.url}/`, {
      headers: { 'x-forwarded-for': '8.8.8.8', 'X-API-Key': BLOCKED_HEADER_VALUE },
    });
    expect(r.status).toBe(403);
    expect(r.headers.get('x-block-rule')).toBe('cr_000000000019');
  });

  it('passes when the header the rule reads is absent', async () => {
    const { a, engine, app } = await v5App();
    const r = await fetch(`${app.url}/`, { headers: { 'x-forwarded-for': '8.8.8.8' } });
    expect(r.status).toBe(200);   // a condition the request cannot answer is false, negatives included
    const ev = (await shipped(a, engine)).at(-1)!;
    expect(ev.blk).toBeUndefined();
    expect(ev.rl).toBeUndefined();
  });

  it('passes a warn rule and stamps wrn on the event', async () => {
    const { a, engine, app } = await v5App();
    const r = await fetch(`${app.url}/`, { headers: { 'x-forwarded-for': '8.8.8.8', 'user-agent': WARN_UA } });
    expect(r.status).toBe(200);
    expect(r.headers.get('x-block-reason')).toBeNull();
    const ev = (await shipped(a, engine)).at(-1)!;
    expect(ev).toMatchObject({ st: 200, wrn: 'cr_00000000000e' });
    expect(ev.blk).toBeUndefined();   // warn is not a block: the traffic passed
  });

  it('leaves an unmatched request alone', async () => {
    const { a, engine, app } = await v5App();
    expect((await fetch(`${app.url}/`, { headers: { 'x-forwarded-for': '8.8.8.8', 'user-agent': 'Mozilla/5.0' } })).status).toBe(200);
    const ev = (await shipped(a, engine)).at(-1)!;
    expect(ev.wrn).toBeUndefined();
    expect(ev.rl).toBeUndefined();
  });
});

describe('snapshot negotiation', () => {
  it('asks for v5 by default', async () => {
    const { a } = await v5App();
    expect(a.snapshotVersions[0]).toBe('5');
  });

  it('opts out of the rules entirely with snapshotVersion: 3', async () => {
    const { a } = await v5App({ snapshotVersion: 3 });
    expect(a.snapshotVersions[0]).toBe('');   // no header at all: the v3 body is the default answer
  });

  it('still enforces against an analyst that only publishes v3', async () => {
    const a = fakeAnalyst();   // v3 container, while the client asks for 5 — §D3's fallback
    const engine = engineWith(a, { CAMADA_TRUSTED_PROXY: 'hops:1' });
    await loaded(engine);
    const app = await serve((req, res) => {
      if (engine.handle(req, res)) return;
      res.writeHead(200).end('app');
    });
    open.push(app, engine);
    expect(a.snapshotVersions[0]).toBe('5');
    const r = await fetch(`${app.url}/`, { headers: { 'x-forwarded-for': BLOCKED_IP, 'user-agent': BLOCKED_UA } });
    expect(r.status).toBe(403);
    expect(r.headers.get('x-block-reason')).toBe('ip4');   // the block side, not a rule
    expect(r.headers.get('x-block-rule')).toBeNull();
  });
});
