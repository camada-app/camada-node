import { createHash, webcrypto } from 'node:crypto';
import { request, type IncomingMessage } from 'node:http';
import { afterEach, expect, it, vi } from 'vitest';
import { powOk } from '@camada/core';
import { BLOCKED_IP, CHALLENGED_IP, engineWith, fakeAnalyst, loaded, serve } from './harness.js';

const credential = 'fake-token-0001-not-a-real-credential';
const auth = { authorization: `Bearer ${credential}` };
const tk = 'b3a18c6c56d5a2f7ad636bf950a919d7';
const cleanup: Array<() => Promise<void>> = [];

afterEach(async () => {
  vi.restoreAllMocks();
  for (const close of cleanup.splice(0).reverse()) await close();
});

async function setup(opts: Parameters<typeof engineWith>[2] = {}, env: Parameters<typeof engineWith>[1] = {}, a = fakeAnalyst()) {
  a.v4 = true;
  const engine = engineWith(a, { CAMADA_KEY: 'ct_test_fixture_key.snap-test', CAMADA_TRUSTED_PROXY: 'hops:1', ...env }, { refreshMs: 60_000, ...opts });
  cleanup.push(() => engine.stop());
  await loaded(engine);
  const app = await serve((req, res) => {
    if (engine.handle(req, res)) return;
    if (req.url === '/track') engine.track(req, 'login');
    res.end('ok');
  });
  cleanup.push(() => app.close());
  const rows = () => a.events.flat() as Array<Record<string, unknown>>;
  const shipped = async (count: number) => {
    await vi.waitFor(async () => {
      await engine.queue!.flush();
      expect(rows()).toHaveLength(count);
    });
    return rows();
  };
  return { app, engine, rows, shipped };
}

it.each([
  { name: 'off by default', opts: {}, env: {}, expected: undefined },
  { name: 'on via the option', opts: { tokenHash: true }, env: {}, expected: tk },
  { name: 'on via the environment', opts: {}, env: { CAMADA_TOKEN_HASH: '1' }, expected: tk },
  { name: 'off when false overrides the environment', opts: { tokenHash: false }, env: { CAMADA_TOKEN_HASH: '1' }, expected: undefined },
])('ships a capture row with hashing $name', async ({ opts, env, expected }) => {
  const { app, shipped } = await setup(opts, env);
  expect(await (await fetch(app.url, { headers: auth })).text()).toBe('ok');
  const [row] = await shipped(1);
  expect(row).toMatchObject({ st: 200 });
  expect(JSON.stringify(row)).not.toContain(credential);
  if (expected === undefined) expect(row).not.toHaveProperty('tk');
  else expect(row).toHaveProperty('tk', expected);
});

it('keeps hashing off when the snapshot requests it', async () => {
  const a = fakeAnalyst();
  a.config.tokenHash = true;
  const { app, shipped } = await setup({}, {}, a);
  expect(await (await fetch(app.url, { headers: auth })).text()).toBe('ok');
  expect((await shipped(1))[0]).not.toHaveProperty('tk');
});

it('ships tk on block, challenge serve, challenge signal, and successful verification rows', async () => {
  const { app, shipped } = await setup({ tokenHash: true });
  const block = await fetch(`${app.url}/blocked`, { headers: { ...auth, 'x-forwarded-for': BLOCKED_IP } });
  expect(block.status).toBe(403);
  await block.text();
  const headers = { ...auth, 'x-forwarded-for': CHALLENGED_IP };
  const signal = await fetch(`${app.url}/api`, { headers: { ...headers, accept: 'application/json' } });
  expect(signal.status).toBe(200);
  expect(signal.headers.get('x-camada-challenge')).toBe('1');
  await signal.text();
  const page = await fetch(`${app.url}/cart`, { headers: { ...headers, accept: 'text/html' } });
  expect(page.status).toBe(403);
  expect(page.headers.get('x-camada-challenge')).toBe('1');
  const nonce = /name="nonce" value="([0-9a-f]{32})"/.exec(await page.text())![1];
  let solution = 0;
  while (!powOk(createHash('sha256').update(`${nonce}.${solution}`).digest('hex'))) solution++;
  const verify = await fetch(`${app.url}/__camada/challenge`, {
    method: 'POST', redirect: 'manual', headers,
    body: new URLSearchParams({ nonce, solution: String(solution), to: '/cart' }),
  });
  expect(verify.status).toBe(302);
  expect(await shipped(4)).toEqual(expect.arrayContaining([
    expect.objectContaining({ st: 403, blk: 'ip4', tk }),
    expect.objectContaining({ st: 403, blk: 'challenge', tk }),
    expect.objectContaining({ st: 200, chs: 1, tk }),
    expect.objectContaining({ st: 200, ch: 1, tk }),
  ]));
});

it('uses the first x-api-key in wire order for an upgrade row', async () => {
  const { app, engine, shipped } = await setup({ tokenHash: true, tokenHeader: 'x-api-key' });
  app.server.on('upgrade', (_req, socket) => {
    socket.end('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n');
  });
  engine.attach(app.server);
  const status = await new Promise<number | undefined>((resolve, reject) => {
    const req = request(`${app.url}/ws`, {
      headers: { ...auth, connection: 'Upgrade', upgrade: 'websocket', 'X-Api-Key': ['fake-api-key-0007', 'second-fake-api-key'] },
    });
    req.on('upgrade', (res, socket) => { socket.destroy(); resolve(res.statusCode); });
    req.on('response', (res) => { res.resume(); resolve(res.statusCode); });
    req.on('error', reject);
    req.end();
  });
  expect(status).toBe(101);
  expect((await shipped(1))[0]).toMatchObject({ st: 101, tk: '94a6878c5d6bc3739f9a3d5644359a38' });
});

it('warns once for an ignored token header and falls back to Authorization', async () => {
  const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
  const { app, shipped } = await setup({ tokenHash: true }, { CAMADA_TOKEN_HEADER: 'cookie' });
  for (const path of ['/first', '/second']) {
    expect(await (await fetch(app.url + path, { headers: auth })).text()).toBe('ok');
  }
  for (const row of await shipped(2)) expect(row).toHaveProperty('tk', tk);
  expect(warn).toHaveBeenCalledTimes(1);
});

it('serves scheme-only Authorization and ships no tk', async () => {
  const { app, shipped } = await setup({ tokenHash: true });
  const res = await fetch(app.url, { headers: { authorization: 'Bearer' } });
  expect(res.status).toBe(200);
  await res.text();
  expect((await shipped(1))[0]).not.toHaveProperty('tk');
});

it('strips tk, bf, and upf from a beacon and omits tk on a track row', async () => {
  const { app, shipped } = await setup({ tokenHash: true });
  const beacon = await fetch(`${app.url}/_cam/fp`, {
    method: 'POST', headers: auth, body: JSON.stringify({ rid: 'beacon', tk, bf: ['field'], upf: ['upload'] }),
  });
  expect(beacon.status).toBe(204);
  expect(await (await fetch(`${app.url}/track`, { headers: auth })).text()).toBe('ok');
  const rows = await shipped(3);
  expect(rows.find((row) => row.p === '/track')).toHaveProperty('tk', tk);
  const signal = rows.find((row) => row.sig === 1);
  expect(signal).toMatchObject({ rid: 'beacon' });
  for (const k of ['tk', 'bf', 'upf']) expect(signal).not.toHaveProperty(k);
  const track = rows.find((row) => row.et === 'login');
  expect(track).toBeDefined();
  expect(track).not.toHaveProperty('tk');
});

it('serves and ships without tk or credential logs when signing rejects', async () => {
  const sign = vi.spyOn((globalThis.crypto ?? webcrypto).subtle, 'sign').mockRejectedValueOnce(new Error(credential));
  const error = vi.spyOn(console, 'error').mockImplementation(() => {});
  const { app, shipped } = await setup({ tokenHash: true });
  const res = await fetch(app.url, { headers: auth });
  expect(res.status).toBe(200);
  expect(await res.text()).toBe('ok');
  expect((await shipped(1))[0]).not.toHaveProperty('tk');
  expect(sign).toHaveBeenCalledTimes(1);
  expect(error).toHaveBeenCalledWith(expect.any(String), 'token hash failed; event ships without tk');
  expect(error.mock.calls.flat().map(String).join(' ')).not.toContain(credential);
});

it('starts the capture POST just after finish in serverless mode without waitUntil', async () => {
  const subtle = (globalThis.crypto ?? webcrypto).subtle;
  const importKey = subtle.importKey.bind(subtle);
  const imported = vi.spyOn(subtle, 'importKey').mockImplementationOnce(async (...args) => {
    await new Promise<void>((resolve) => setImmediate(resolve));
    return importKey(...args);
  });
  const signed = vi.spyOn(subtle, 'sign');
  const a = fakeAnalyst();
  const engine = engineWith(a, { CAMADA_KEY: 'ct_test_fixture_key.snap-test', CAMADA_SERVERLESS: '1' }, { tokenHash: true });
  cleanup.push(() => engine.stop());
  await loaded(engine);
  const app = await serve(async (req, res) => {
    if (engine.handle(req, res)) return;
    // Give hashing that started during handle() time to settle while the app runs.
    await imported.mock.results[0]?.value;
    await signed.mock.results[0]?.value;
    res.end('ok');
  });
  cleanup.push(() => app.close());
  const postedAtFinish = new Promise<unknown[]>((resolve) => {
    app.server.prependOnceListener('request', (_req, res) => {
      res.once('finish', () => setImmediate(() => resolve(a.events.flat())));
    });
  });
  expect(await (await fetch(app.url, { headers: auth })).text()).toBe('ok');
  expect(await postedAtFinish).toEqual([expect.objectContaining({ st: 200, tk })]);
});

it('hands pending hashing to waitUntil in serverless mode', async () => {
  const subtle = (globalThis.crypto ?? webcrypto).subtle;
  const realSign = subtle.sign.bind(subtle);
  let release!: () => void;
  const pending = new Promise<void>((resolve) => { release = resolve; });
  vi.spyOn(subtle, 'sign').mockImplementationOnce(async (...args) => {
    await pending;
    return realSign(...args);
  });
  const held: Promise<unknown>[] = [];
  const { app, rows } = await setup({ tokenHash: true, waitUntil: (p) => { held.push(p); } }, { CAMADA_SERVERLESS: '1' });
  try {
    expect(await (await fetch(app.url, { headers: auth })).text()).toBe('ok');
    expect(held).toHaveLength(1);
    expect(rows()).toHaveLength(0);
  } finally {
    release();
  }
  await held[0];
  expect(held).toHaveLength(2);
  await held[1];
  expect(rows()).toEqual([expect.objectContaining({ st: 200, tk })]);
});

it('drains a timer-mode capture whose hash is pending when stop() starts', async () => {
  const { app, engine, rows } = await setup({ tokenHash: true });
  const subtle = (globalThis.crypto ?? webcrypto).subtle;
  const sign = subtle.sign.bind(subtle);
  let release!: () => void;
  const pending = new Promise<void>((resolve) => { release = resolve; });
  vi.spyOn(subtle, 'sign').mockImplementationOnce(async (...args) => {
    await pending;
    return sign(...args);
  });
  let stopping: Promise<void>;
  try {
    expect(await (await fetch(app.url, { headers: auth })).text()).toBe('ok');
    stopping = engine.stop();
  } finally {
    release();
  }
  await stopping;
  expect(rows()).toEqual([expect.objectContaining({ st: 200, tk })]);
});

it('batches a serverless track after finish with the pending capture hash', async () => {
  const a = fakeAnalyst();
  const { app, engine } = await setup({ tokenHash: true }, { CAMADA_SERVERLESS: '1' }, a);
  const subtle = (globalThis.crypto ?? webcrypto).subtle;
  const sign = subtle.sign.bind(subtle);
  let release!: () => void;
  const pending = new Promise<void>((resolve) => { release = resolve; });
  vi.spyOn(subtle, 'sign').mockImplementationOnce(async (...args) => {
    await pending;
    return sign(...args);
  });
  let req!: IncomingMessage;
  app.server.once('request', (incoming) => { req = incoming; });
  try {
    expect(await (await fetch(app.url, { headers: auth })).text()).toBe('ok');
    engine.track(req, 'login');
    await new Promise<void>((resolve) => setImmediate(resolve));
  } finally {
    release();
  }
  await vi.waitFor(() => expect(a.events.flat()).toHaveLength(2));
  expect(a.events).toEqual([[
    expect.objectContaining({ et: 'login' }),
    expect.objectContaining({ st: 200, tk }),
  ]]);
});
