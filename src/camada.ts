// The engine: node:http-level request handling every adapter delegates to.
//   camada.handle(req, res) -> true when camada fully answered the request (block or beacon
//   endpoint), false when the app should proceed. Everything runs inside the fail-open
//   envelope: a camada bug must never 5xx the customer (plan.md INT-2), and CAMADA_DISABLED=1
//   bypasses the SDK entirely.
import type { IncomingMessage, ServerResponse } from 'node:http';
import { randomUUID } from 'node:crypto';
import {
  SnapshotClient, EventQueue, buildWireEvent, resolveClientIp, hashUserId, guarded, logRateLimited,
  TAP_NODE, type TrustedProxyConfig, type WireEvent,
} from '@camada/core';
import iife from '@camada/browser/iife-string';
import { resolveEnv, type ResolvedEnv } from './env.js';

const SESSION_COOKIE = '_sfp';   // same cookie as the edge collector: sid/ns comparable across taps
const SCRIPT_PATH = '/_cam/b.js';
const FP_PATH = '/_cam/fp';
const FP_MAX = 64 * 1024;

export interface CamadaOptions {
  env?: Record<string, string | undefined>;
  fetchImpl?: typeof fetch;      // threaded into snapshot client, event queue, and the fp relay (tests)
  refreshMs?: number;
  scriptPath?: string;
  fpPath?: string;
}

interface CamadaRequest extends IncomingMessage {
  camada?: { rid: string; ip: string | null; sid: string };
  route?: { path?: string };     // Express fills this after routing
}

const cookieValue = (cookie: string, name: string): string | null => {
  const src = '; ' + cookie;
  const i = src.indexOf('; ' + name + '=');
  if (i === -1) return null;
  const start = i + name.length + 3;
  const j = src.indexOf(';', start);
  return src.slice(start, j === -1 ? undefined : j);
};

export class Camada {
  readonly env: ResolvedEnv | null;
  readonly snap: SnapshotClient | null = null;
  readonly queue: EventQueue | null = null;
  private readonly fetchImpl: typeof fetch;
  private readonly scriptPath: string;
  private readonly fpPath: string;
  private readonly envSource: Record<string, string | undefined>;

  constructor(opts: CamadaOptions = {}) {
    this.envSource = opts.env ?? process.env;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.scriptPath = opts.scriptPath ?? SCRIPT_PATH;
    this.fpPath = opts.fpPath ?? FP_PATH;
    this.env = resolveEnv(this.envSource);
    if (!this.env) return;                       // unconfigured: every entry point no-ops
    this.snap = new SnapshotClient({
      url: this.env.snapshotUrl, token: this.env.snapToken,
      mode: this.env.serverless ? 'lazy' : 'timer',
      refreshMs: opts.refreshMs, fetchImpl: this.fetchImpl,
    });
    this.queue = new EventQueue({ url: this.env.ingestUrl, token: this.env.ingestToken, fetchImpl: this.fetchImpl });
    this.snap.start();
    this.queue.installNodeExitFlush();
  }

  get disabled(): boolean { return this.envSource.CAMADA_DISABLED === '1' || !this.env; }

  private trustedProxy(): TrustedProxyConfig | null {
    return this.env?.trustedProxy ?? this.snap?.config?.trusted_proxy ?? null;   // explicit local override wins
  }

  private beaconEnabled(): boolean { return this.snap?.config?.beacon !== false; }

  /** True when camada fully handled the request. Synchronous; never throws. */
  handle(req: IncomingMessage, res: ServerResponse): boolean {
    return guarded(() => this.handleInner(req as CamadaRequest, res), false);
  }

  private handleInner(req: CamadaRequest, res: ServerResponse): boolean {
    if (this.disabled || !this.snap || !this.queue || !this.env) return false;
    const t0 = Date.now();
    this.snap.ensureFresh();

    const rawUrl = req.url || '/';
    const qi = rawUrl.indexOf('?');
    const path = qi === -1 ? rawUrl : rawUrl.slice(0, qi);
    const query = qi === -1 ? '' : rawUrl.slice(qi);
    const ip = resolveClientIp(req.socket?.remoteAddress, req.headers['x-forwarded-for'] as string | undefined, this.trustedProxy());

    // enforce before anything else, beacon endpoints included — fail open while cold
    const v = this.snap.verdict({ ip, path });
    if (v.block) {
      res.writeHead(403, { 'x-block-reason': v.reason ?? '', 'x-block-version': v.version ?? '', 'content-type': 'text/plain' });
      res.end('Forbidden');
      const ev = this.buildEvent(req, path, query, ip, { rid: randomUUID(), sid: null, newSession: false });
      ev.st = 403;   // blocked requests always ship: silent expiry makes blocks oscillate
      this.queue.push(ev);
      return true;
    }

    if (this.beaconEnabled()) {
      if (req.method === 'GET' && path === this.scriptPath) {
        res.writeHead(200, { 'content-type': 'application/javascript', 'cache-control': 'public, max-age=3600' });
        res.end(iife);
        return true;
      }
      if (req.method === 'POST' && path === this.fpPath) {
        this.relayBeacon(req, res, ip);
        return true;
      }
    }

    const rid = randomUUID();
    let sid = cookieValue((req.headers.cookie as string) || '', SESSION_COOKIE);
    const newSession = !sid;
    if (!sid) {
      sid = randomUUID();
      res.setHeader('set-cookie', `${SESSION_COOKIE}=${sid}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax`);
    }
    req.camada = { rid, ip, sid };
    res.setHeader('x-rid', rid);

    const cfg = this.snap.config;
    const excluded = (cfg?.exclude || []).some((x) => path.startsWith(x));
    if (!excluded && Math.random() < (cfg?.sample ?? 1)) {
      res.on('finish', () => guarded(() => {
        const ev = this.buildEvent(req, path, query, ip, { rid, sid, newSession });
        ev.st = res.statusCode;
        ev.dur = Date.now() - t0;
        if (req.route?.path) ev.rt = String(req.route.path);
        this.queue!.push(ev);
      }, undefined));
    }
    return false;
  }

  private buildEvent(req: CamadaRequest, path: string, query: string, ip: string | null, o: { rid: string; sid: string | null; newSession: boolean }): WireEvent {
    const raw = req.rawHeaders || [];
    const headers: Array<[string, string]> = [];
    for (let i = 0; i + 1 < raw.length; i += 2) headers.push([raw[i], raw[i + 1]]);
    return buildWireEvent(
      { method: req.method || 'GET', host: (req.headers.host as string) || '', path, query, headers, ip, httpVersion: req.httpVersion },
      { tap: TAP_NODE, rid: o.rid, sid: o.sid, newSession: o.newSession },
    );
  }

  /** Reads the beacon POST (≤64 KB), answers 204 immediately, relays to ingest with the
   *  trusted-proxy-resolved client IP — the mirror of the edge collector's /__fp path. */
  private relayBeacon(req: IncomingMessage, res: ServerResponse, ip: string | null): void {
    const chunks: Buffer[] = [];
    let size = 0, dead = false;
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > FP_MAX) { dead = true; req.removeAllListeners('data'); res.writeHead(413).end(); return; }
      chunks.push(c);
    });
    req.on('end', () => guarded(() => {
      if (dead) return;
      res.writeHead(204, { 'cache-control': 'no-store' });
      res.end();
      let body = Buffer.concat(chunks).toString('utf8');
      try { body = JSON.stringify({ ...JSON.parse(body), tap: TAP_NODE }); } catch { /* relay as-is; the server validates */ }
      void this.fetchImpl(`${this.env!.ingestUrl}/fp`, {
        method: 'POST',
        headers: { 'x-tenant': this.env!.ingestToken, 'content-type': 'application/json', 'x-client-ip': ip || '' },
        body,
        signal: AbortSignal.timeout(2000),
      }).catch(() => {});
    }, undefined));
    req.on('error', () => { try { res.destroy(); } catch { /* already gone */ } });
  }

  /** For HTML templates: the first-party beacon tag with the request's rid. */
  scriptTag(req: IncomingMessage): string {
    if (this.disabled || !this.beaconEnabled()) return '';
    const rid = (req as CamadaRequest).camada?.rid;
    return `<script src="${this.scriptPath}${rid ? `?r=${rid}` : ''}" async></script>`;
  }

  /** App-context outcome events (login failed, signup, …). The identifier is HMAC-hashed
   *  in-process; the raw value never reaches the queue. */
  track(req: IncomingMessage, event: string, data?: { user?: string }): void {
    guarded(() => {
      if (this.disabled || !this.queue || !this.env) return;
      const ctx = (req as CamadaRequest).camada;
      void (async () => {
        const uid = data?.user ? await hashUserId(data.user, this.env!.ingestToken) : null;
        this.queue!.push({ tap: TAP_NODE, et: event, uid, rid: ctx?.rid ?? null, sid: ctx?.sid ?? null, ip: ctx?.ip ?? null, ts: Date.now() });
      })().catch(logRateLimited);
    }, undefined);
  }

  /** Express/Connect middleware (also what NestJS on the default platform consumes). */
  express() {
    return (req: IncomingMessage, res: ServerResponse, next: (err?: unknown) => void): void => {
      if (!this.handle(req, res)) next();
    };
  }

  stop(): void {
    this.snap?.stop();
    this.queue?.stop();
  }
}

export function createCamada(opts: CamadaOptions = {}): Camada {
  const c = new Camada(opts);
  if (!c.env) logRateLimited(new Error('CAMADA_KEY (or CAMADA_TOKEN + CAMADA_SNAPSHOT_TOKEN) not set — camada is inactive'));
  return c;
}
