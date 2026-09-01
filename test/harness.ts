// Shared test harness: an in-process fetch router standing in for the analyst Worker
// (GET /snapshot, POST /e, POST /fp), plus a real node:http server helper.
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createCamada, type CamadaOptions } from '../src/index.js';

// the same golden fixtures camada-core is pinned to, read through the file: symlink
const FIX = join(process.cwd(), 'node_modules', '@camada/core', 'test', 'fixtures');
export const BIN = readFileSync(join(FIX, 'snap-basic.bin'));
export const META = JSON.stringify(JSON.parse(readFileSync(join(FIX, 'snap-basic.meta.json'), 'utf8')));
export const BLOCKED_IP = '203.0.113.66';   // an ip4 entry in snap-basic

export interface FakeAnalyst {
  fetchImpl: typeof fetch;
  events: unknown[][];          // batches POSTed to /e
  beacons: Array<{ body: string; clientIp: string | null }>;
  config: Record<string, unknown>;
  snapshotDown: boolean;
  ingestDown: boolean;
}

export function fakeAnalyst(): FakeAnalyst {
  const a: FakeAnalyst = {
    events: [], beacons: [], snapshotDown: false, ingestDown: false,
    config: { tenant: 'acme', beacon: true, sample: 1, exclude: [], trusted_proxy: { mode: 'none' }, poll_seconds: 30 },
    fetchImpl: (async (url: string | URL | Request, init?: RequestInit) => {
      const u = String(url);
      if (u.endsWith('/snapshot')) {
        if (a.snapshotDown) throw new Error('ECONNREFUSED');
        // 200 body frame: [u32 LE meta-length][meta JSON][BLK3 bin]
        const m = new TextEncoder().encode(META);
        const f = new Uint8Array(4 + m.length + BIN.length);
        new DataView(f.buffer).setUint32(0, m.length, true);
        f.set(m, 4); f.set(new Uint8Array(BIN), 4 + m.length);
        return new Response(f, {
          status: 200,
          headers: { etag: `"${JSON.parse(META).version}"`, 'x-camada-config': JSON.stringify(a.config) },
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
