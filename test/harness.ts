// Shared test harness: an in-process fetch router standing in for the analyst Worker
// (GET /snapshot, POST /e, POST /fp), plus a real node:http server helper.
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createCamada, type CamadaOptions } from '../src/index.js';

// the same golden fixtures camada-core is pinned to, read through the file: symlink
const FIX = join(process.cwd(), 'node_modules', '@camada/core', 'test', 'fixtures', 'blk3');
export const BIN = readFileSync(join(FIX, 'v3-basic.bin'));
export const META = JSON.stringify(JSON.parse(readFileSync(join(FIX, 'v3-basic.meta.json'), 'utf8')));
export const V4_BIN = readFileSync(join(FIX, 'v4-basic.bin'));
export const V4_META = JSON.stringify(JSON.parse(readFileSync(join(FIX, 'v4-basic.meta.json'), 'utf8')));
export const BLOCKED_IP = '203.0.113.66';   // an ip4 entry in v3-basic and v4-basic
export const CHALLENGED_IP = '192.0.2.20';   // a challenge-only ip4 entry in v4-basic
export const ALLOWED_IP = '10.0.0.7';       // allow-listed inside the blocked 10.0.0.0/8

export interface FakeAnalyst {
  fetchImpl: typeof fetch;
  events: unknown[][];          // batches POSTed to /e
  beacons: Array<{ body: string; clientIp: string | null }>;
  sdkHeaders: string[];         // x-camada-sdk seen on /snapshot and /e
  config: Record<string, unknown>;
  snapshotDown: boolean;
  ingestDown: boolean;
  v4: boolean;                  // serve the v4 golden container instead of v3
  snapshotVersions: string[];   // x-camada-snapshot seen on /snapshot
}

export function fakeAnalyst(): FakeAnalyst {
  const a: FakeAnalyst = {
    events: [], beacons: [], sdkHeaders: [], snapshotVersions: [], snapshotDown: false, ingestDown: false, v4: false,
    config: { tenant: 'acme', beacon: true, sample: 1, exclude: [], trusted_proxy: { mode: 'none' }, poll_seconds: 30 },
    fetchImpl: (async (url: string | URL | Request, init?: RequestInit) => {
      const u = String(url);
      if (u.endsWith('/snapshot') || u.endsWith('/e')) a.sdkHeaders.push(new Headers(init?.headers).get('x-camada-sdk') ?? '');
      if (u.endsWith('/snapshot')) {
        a.snapshotVersions.push(new Headers(init?.headers).get('x-camada-snapshot') ?? '');
        if (a.snapshotDown) throw new Error('ECONNREFUSED');
        // 200 body frame: [u32 LE meta-length][meta JSON][BLK3 bin]
        const meta = a.v4 ? V4_META : META, body = a.v4 ? V4_BIN : BIN;
        const m = new TextEncoder().encode(meta);
        const f = new Uint8Array(4 + m.length + body.length);
        new DataView(f.buffer).setUint32(0, m.length, true);
        f.set(m, 4); f.set(new Uint8Array(body), 4 + m.length);
        return new Response(f, {
          status: 200,
          headers: { etag: `"${JSON.parse(meta).version}"`, 'x-camada-config': JSON.stringify(a.config) },
        });
      }
      if (a.ingestDown) throw new Error('ECONNREFUSED');
      if (u.endsWith('/e')) { a.events.push(JSON.parse(init!.body as string)); return new Response(null, { status: 202 }); }
      if (u.endsWith('/fp')) {
        a.beacons.push({ body: init!.body as string, clientIp: new Headers(init?.headers).get('x-client-ip') });
        return new Response(null, { status: 202 });
      }
      throw new Error('unmocked fetch: ' + u);
    }) as typeof fetch,
  };
  return a;
}

export const ENV = {
  CAMADA_KEY: 'tok-test.snap-test',
  CAMADA_INGEST_URL: 'https://analyst.test',
} as Record<string, string>;

export function engineWith(analyst: FakeAnalyst, env: Record<string, string | undefined> = {}, opts: Partial<CamadaOptions> = {}) {
  return createCamada({ env: { ...ENV, ...env }, fetchImpl: analyst.fetchImpl, refreshMs: 5, ...opts });
}

export async function loaded(engine: ReturnType<typeof createCamada>): Promise<void> {
  for (let i = 0; i < 100; i++) {
    if (engine.snap && engine.snap.verdict({ ip: '0.0.0.0' }).reason !== 'cold') return;
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error('snapshot never loaded');
}

export interface App { server: Server; port: number; url: string; close(): Promise<void> }

export function serve(handler: (req: IncomingMessage, res: ServerResponse) => void): Promise<App> {
  const server = createServer(handler);
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const port = (server.address() as { port: number }).port;
      resolve({ server, port, url: `http://127.0.0.1:${port}`, close: () => new Promise((r) => server.close(() => r())) });
    });
  });
}

export const settle = (ms = 25) => new Promise((r) => setTimeout(r, ms));
