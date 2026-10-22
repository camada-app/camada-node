// CAMADA_TLSX_HEADER (camada-all-8pn9): the TLS fingerprint a trusted proxy (a Cloudflare Transform
// Rule) writes into a header feeds core's matcher, so v3/v4 `tls` entries and v5 `tlsx` rule
// conditions bite on node like on @camada/core based SDKs. It is believed only in cidrs mode from a
// trusted-proxy peer, and the same trusted value rides the wire event (camada-all-bcsf).
import { describe, it, expect, afterEach } from 'vitest';
import { Socket } from 'node:net';
import { IncomingMessage, ServerResponse } from 'node:http';
import type { Camada } from '../src/index.js';
import type { TrustedProxyConfig } from '@camada/core';
import { fakeAnalyst, engineWith, loaded, settle, V5_META, ALLOWED_IP, CHALLENGED_IP, type FakeAnalyst } from './harness.js';

const open: Camada[] = [];
afterEach(() => { for (const e of open.splice(0)) e.stop(); });

const TLSX = '9f0a77c2';              // the `tls` entry of the v3/v4/v5 golden containers
const TRUSTED = '198.18.0.5';         // inside CIDRS
const CIDRS = 'cidrs:198.18.0.0/15';
const HDR = 'x-camada-tlsx';

/** v5 golden meta with tlsx rules in front: `is`, `is_in`, and an AND with an ip set. The ip set a rule uses is the golden bin's
 *  set at that rule's index, so the AND sits at index 1, where the set holds ALLOWED_IP (10.0.0.0/8). */
const RULES_META = JSON.stringify({
  ...JSON.parse(V5_META), version: 'tlsx-rules',
  rules: [
    { id: 'cr_tlsx_is', action: 'block', conds: [{ f: 'tlsx', op: 'is', v: 'aaaa1111' }] },
    { id: 'cr_tlsx_and_ip', action: 'block', conds: [{ f: 'ip', op: 'is_in', set: true }, { f: 'tlsx', op: 'is', v: 'dddd4444' }] },
    { id: 'cr_tlsx_in', action: 'block', conds: [{ f: 'tlsx', op: 'is_in', v: ['bbbb2222', 'cccc3333'] }] },
  ],
});

async function engine(a: FakeAnalyst, env: Record<string, string | undefined> = {}, opts: Parameters<typeof engineWith>[2] = {}) {
  if (a.v5 && !a.v4) a.v5Meta = RULES_META;   // swap the golden v5 meta for the tlsx rules over the same bin
  const e = engineWith(a, { CAMADA_TLSX_HEADER: HDR, CAMADA_TRUSTED_PROXY: CIDRS, ...env }, opts);
  open.push(e);
  await loaded(e);
  a.events.length = 0;
  return e;
}

/** One request through handle() with a chosen socket peer (`null`: a TCP socket that has none). */
function hit(e: Camada, peer: string | null, headers: Record<string, string | string[]> = {}) {
  const sock = new Socket();
  Object.defineProperty(sock, 'remoteAddress', { value: peer ?? undefined });
  const req = new IncomingMessage(sock);
  Object.assign(req, { method: 'GET', url: '/', headers: { host: 'a', ...headers } });
  const res = new ServerResponse(req);
  const blocked = e.handle(req, res);
  sock.destroy();
  // writeHead(status, headers) serialises straight into the raw head, so read the names from there
  const head = (name: string) => new RegExp(`^${name}: (.*)$`, 'mi').exec((res as unknown as { _header?: string })._header ?? '')?.[1];
  return { blocked, res, reason: head('x-block-reason'), rule: head('x-block-rule') };
}

describe('tlsx header, v3 tls entry', () => {
  it('blocks a trusted-proxy peer with reason tls and ships blk tls on the event', async () => {
    const a = fakeAnalyst();
    const e = await engine(a);
    const r = hit(e, TRUSTED, { [HDR]: TLSX });
    expect(r.res.statusCode).toBe(403);
    expect(r.reason).toBe('tls');
    await settle(); await e.queue!.flush();
    const evs = a.events.flat() as Array<Record<string, unknown>>;
    expect(evs).toHaveLength(1);
    expect(evs[0]).toMatchObject({ st: 403, blk: 'tls' });
  });

  it.each(['127.0.0.1', '127.1.2.3', '::1', '::ffff:127.0.0.1'])('ignores the header from loopback peer %s, even with a trusted-cidr XFF', async (peer) => {
    const e = await engine(fakeAnalyst());
    expect(hit(e, peer, { [HDR]: TLSX }).blocked).toBe(false);
    expect(hit(e, peer, { [HDR]: TLSX, 'x-forwarded-for': TRUSTED }).blocked).toBe(false);
    expect(hit(e, peer, { [HDR]: TLSX, 'x-forwarded-for': `8.8.8.8, ${TRUSTED}` }).blocked).toBe(false);
  });

  it('ignores XFF for a trusted non-loopback peer too', async () => {
    const e = await engine(fakeAnalyst());
    expect(hit(e, TRUSTED, { [HDR]: TLSX, 'x-forwarded-for': '8.8.8.8' }).reason).toBe('tls');
  });

  it('trusts peers inside the configured cidrs', async () => {
    const e = await engine(fakeAnalyst(), { CAMADA_TRUSTED_PROXY: 'cidrs:192.0.2.0/24' });
    expect(hit(e, '192.0.2.1', { [HDR]: TLSX }).reason).toBe('tls');
    expect(hit(e, '192.0.2.77', { [HDR]: TLSX }).reason).toBe('tls');
  });

  it('trusts a peer inside cidrs wide enough to hold every RFC 5737 range', async () => {
    const e = await engine(fakeAnalyst(), { CAMADA_TRUSTED_PROXY: 'cidrs:192.0.0.0/4' });
    expect(hit(e, '205.0.0.9', { [HDR]: TLSX }).reason).toBe('tls');
  });

  it('takes the header name from the tlsxHeader option too, lower-cased', async () => {
    const e = await engine(fakeAnalyst(), { CAMADA_TLSX_HEADER: undefined }, { tlsxHeader: 'X-Fp' });
    expect(hit(e, TRUSTED, { 'x-fp': TLSX }).reason).toBe('tls');
  });

  it('ignores the header from a peer outside the cidrs, including a documentation address', async () => {
    const e = await engine(fakeAnalyst());
    expect(hit(e, '8.8.8.8', { [HDR]: TLSX }).blocked).toBe(false);
    expect(hit(e, '192.0.2.1', { [HDR]: TLSX }).blocked).toBe(false);
  });

  it.each(['none', 'hops:1', 'vercel'])('ignores the header in %s mode', async (mode) => {
    const e = await engine(fakeAnalyst(), { CAMADA_TRUSTED_PROXY: mode });
    expect(hit(e, TRUSTED, { [HDR]: TLSX }).blocked).toBe(false);
  });

  it('ignores the header in a mode the server config delivers (no local override) unless it is cidrs', async () => {
    const a = fakeAnalyst();   // trusted_proxy: none from the server
    const e = await engine(a, { CAMADA_TRUSTED_PROXY: undefined });
    expect(hit(e, TRUSTED, { [HDR]: TLSX }).blocked).toBe(false);
    const b = fakeAnalyst(); b.config.trusted_proxy = { mode: 'cidrs', cidrs: ['198.18.0.0/15'] };
    const e2 = await engine(b, { CAMADA_TRUSTED_PROXY: undefined });
    expect(hit(e2, TRUSTED, { [HDR]: TLSX }).reason).toBe('tls');
  });

  it('ignores the header when the env var is unset', async () => {
    const e = await engine(fakeAnalyst(), { CAMADA_TLSX_HEADER: undefined });
    expect(hit(e, TRUSTED, { [HDR]: TLSX }).blocked).toBe(false);
  });

  it('ignores a malformed value: too long, outside the charset, repeated', async () => {
    const e = await engine(fakeAnalyst());
    expect(hit(e, TRUSTED, { [HDR]: 'a'.repeat(129) }).blocked).toBe(false);
    expect(hit(e, TRUSTED, { [HDR]: TLSX + ' x' }).blocked).toBe(false);
    expect(hit(e, TRUSTED, { [HDR]: '9f0a77c2!' }).blocked).toBe(false);
    expect(hit(e, TRUSTED, { [HDR]: `${TLSX}, ${TLSX}` }).blocked).toBe(false);
    expect(hit(e, TRUSTED, { [HDR]: [TLSX, TLSX] }).blocked).toBe(false);
  });

  it('ignores the header on a TCP socket with no readable peer', async () => {
    const e = await engine(fakeAnalyst());
    expect(hit(e, null, { [HDR]: TLSX }).blocked).toBe(false);
  });
});

describe('config reads', () => {
  const counted = () => {
    const state = { reads: 0 };
    const cfg = { mode: 'cidrs', get cidrs() { state.reads++; return ['198.18.0.0/15']; } } as unknown as TrustedProxyConfig;
    return { state, cfg };
  };

  it('does not read the trust config when the header is absent', async () => {
    const e = await engine(fakeAnalyst());
    const c = counted();
    (e as unknown as { trustedProxy: () => TrustedProxyConfig }).trustedProxy = () => c.cfg;
    hit(e, TRUSTED);
    expect(c.state.reads).toBe(0);
  });
});

describe('tlsx header, v4', () => {
  it('lets an allowlisted IP pass despite a blocked tls entry', async () => {
    const a = fakeAnalyst(); a.v4 = true;
    const e = await engine(a);
    expect(hit(e, TRUSTED, { [HDR]: TLSX }).reason).toBe('tls');
    expect(hit(e, TRUSTED, { [HDR]: TLSX, 'x-forwarded-for': ALLOWED_IP }).blocked).toBe(false);
  });
});

describe('tlsx header, v5 rules', () => {
  const v5 = async () => { const a = fakeAnalyst(); a.v5 = true; return { a, e: await engine(a) }; };

  it('blocks on `tlsx is` with x-block-rule', async () => {
    const { e } = await v5();
    const r = hit(e, TRUSTED, { [HDR]: 'aaaa1111' });
    expect(r.res.statusCode).toBe(403);
    expect([r.reason, r.rule]).toEqual(['rule', 'cr_tlsx_is']);
  });

  it('blocks on `tlsx is_in` with x-block-rule', async () => {
    const { e } = await v5();
    expect(hit(e, TRUSTED, { [HDR]: 'cccc3333' }).rule).toBe('cr_tlsx_in');
  });

  it('fails open with no header, and the rules ignore an untrusted peer', async () => {
    const { e } = await v5();
    expect(hit(e, TRUSTED).blocked).toBe(false);
    expect(hit(e, '8.8.8.8', { [HDR]: 'aaaa1111' }).blocked).toBe(false);
  });

  it('fails open inside an AND with an ip condition when there is no header', async () => {
    const { e } = await v5();
    const xff = { 'x-forwarded-for': ALLOWED_IP };
    expect(hit(e, TRUSTED, { ...xff, [HDR]: 'dddd4444' }).rule).toBe('cr_tlsx_and_ip');
    expect(hit(e, TRUSTED, xff).blocked).toBe(false);
    expect(hit(e, TRUSTED, { [HDR]: 'dddd4444' }).blocked).toBe(false);   // right header, ip outside the set
  });
});

describe('wire event', () => {
  const HTML = { accept: 'text/html', 'sec-fetch-dest': 'document' };
  const rows = async (a: FakeAnalyst, e: Camada) => { await settle(); await e.queue!.flush(); return (a.events.flat() as Array<Record<string, unknown>>); };
  /** One request per scenario; every event it ships must carry no tlsx key. */
  const noTlsx = async (e: Camada, a: FakeAnalyst, peer: string | null, headers: Record<string, string | string[]>) => {
    const r = hit(e, peer, headers);
    r.res.emit('finish');
    const evs = await rows(a, e);
    a.events.length = 0;
    expect(evs.length).toBeGreaterThanOrEqual(1);
    for (const ev of evs) expect(ev).not.toHaveProperty('tlsx');
  };

  it('carries tlsx on the pass event and the 403 tls block event from a trusted peer', async () => {
    const a = fakeAnalyst();
    const e = await engine(a);
    hit(e, TRUSTED, { [HDR]: TLSX });                       // blocked (tls)
    hit(e, TRUSTED, { [HDR]: 'ffff0000' }).res.emit('finish');   // passes
    const evs = await rows(a, e);
    expect(evs).toHaveLength(2);
    expect(evs.find((ev) => ev.blk === 'tls')).toMatchObject({ st: 403, tlsx: TLSX });
    expect(evs.find((ev) => ev.blk !== 'tls')).toMatchObject({ tlsx: 'ffff0000' });
  });

  it('carries tlsx on a 403 rule block event', async () => {
    const a = fakeAnalyst(); a.v5 = true;
    const e = await engine(a);
    expect(hit(e, TRUSTED, { [HDR]: 'aaaa1111' }).rule).toBe('cr_tlsx_is');
    expect(await rows(a, e)).toEqual([expect.objectContaining({ st: 403, blk: 'rule', tlsx: 'aaaa1111' })]);
  });

  it('carries tlsx on the challenge-serve event', async () => {
    const a = fakeAnalyst(); a.v4 = true;
    const e = await engine(a);
    const r = hit(e, TRUSTED, { ...HTML, [HDR]: 'ffff0000', 'x-forwarded-for': CHALLENGED_IP });
    expect(r.res.statusCode).toBe(403);
    expect(await rows(a, e)).toEqual([expect.objectContaining({ st: 403, blk: 'challenge', tlsx: 'ffff0000' })]);
  });

  it('ships no tlsx from a peer outside the cidrs, including a probe address', async () => {
    const a = fakeAnalyst(); const e = await engine(a);
    await noTlsx(e, a, '8.8.8.8', { [HDR]: TLSX });
    await noTlsx(e, a, '192.0.2.1', { [HDR]: TLSX });
  });

  it.each(['none', 'hops:1', 'vercel'])('ships no tlsx in %s mode', async (mode) => {
    const a = fakeAnalyst();
    const e = await engine(a, { CAMADA_TRUSTED_PROXY: mode });
    await noTlsx(e, a, TRUSTED, { [HDR]: TLSX });
  });

  it('ships no tlsx when the trusted-proxy mode is unset (server config none)', async () => {
    const a = fakeAnalyst();
    const e = await engine(a, { CAMADA_TRUSTED_PROXY: undefined });
    await noTlsx(e, a, TRUSTED, { [HDR]: TLSX });
  });

  it('ships no tlsx when the env var is unset', async () => {
    const a = fakeAnalyst();
    const e = await engine(a, { CAMADA_TLSX_HEADER: undefined });
    await noTlsx(e, a, TRUSTED, { [HDR]: TLSX });
  });

  it('ships no tlsx for a malformed, over-long or repeated value', async () => {
    const a = fakeAnalyst(); const e = await engine(a);
    for (const v of ['a'.repeat(129), TLSX + ' x', '9f0a77c2!', `${TLSX}, ${TLSX}`, [TLSX, TLSX]]) await noTlsx(e, a, TRUSTED, { [HDR]: v });
  });

  it.each(['127.0.0.1', '::1', '::ffff:127.0.0.1'])('ships no tlsx from loopback peer %s', async (peer) => {
    const a = fakeAnalyst(); const e = await engine(a);
    await noTlsx(e, a, peer, { [HDR]: TLSX, 'x-forwarded-for': TRUSTED });
  });

  it('ships no tlsx with no readable peer', async () => {
    const a = fakeAnalyst(); const e = await engine(a);
    await noTlsx(e, a, null, { [HDR]: TLSX });
  });

  it('never puts tlsx on a track() row or a beacon-relay row', async () => {
    const a = fakeAnalyst();
    const e = await engine(a);
    const sock = new Socket();
    Object.defineProperty(sock, 'remoteAddress', { value: TRUSTED });
    const req = new IncomingMessage(sock);
    Object.assign(req, { method: 'GET', url: '/', headers: { host: 'a', [HDR]: 'ffff0000' } });
    const res = new ServerResponse(req);
    e.handle(req, res);
    res.emit('finish');
    e.track(req, 'login_failed', { user: 'u' });
    const bres = new ServerResponse(req);
    const beacon = new IncomingMessage(sock);
    Object.assign(beacon, { method: 'POST', url: '/_cam/fp', headers: { host: 'a', [HDR]: 'ffff0000' }, body: { rid: 'abc', tz: 'UTC' } });
    Object.defineProperty(beacon, 'readableEnded', { value: true });
    e.handle(beacon, bres);
    const evs = await rows(a, e);
    sock.destroy();
    expect(evs.find((ev) => ev.et === 'login_failed')).toBeDefined();
    expect(evs.find((ev) => ev.sig === 1)).toBeDefined();
    expect(evs.find((ev) => !ev.et && !ev.sig)).toHaveProperty('tlsx', 'ffff0000');   // the request row does
    for (const ev of evs.filter((x) => x.et || x.sig)) expect(ev).not.toHaveProperty('tlsx');
  });
});
