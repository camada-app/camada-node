// The engine: node:http-level request handling every adapter delegates to.
//   camada.handle(req, res) -> true when camada fully answered the request (block or beacon
//   endpoint), false when the app should proceed. Everything runs inside the fail-open
//   envelope: a camada bug must never 5xx the customer (plan.md INT-2), and CAMADA_DISABLED=1
//   bypasses the SDK entirely.
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { randomUUID, webcrypto } from 'node:crypto';   // webcrypto handed to hashUserId explicitly, so the hash never depends on which global the host exposes
import {
  SnapshotClient, EventQueue, buildWireEvent, resolveClientIp, hashUserId, guarded, logRateLimited,
  challengePage, challengeCookie, safeReturnTo, wantsHtml, parseFormBody, CHALLENGE_COOKIE,
  TAP_NODE, type ChallengeKit, type SnapshotVersion, type TrustedProxyConfig, type WireEvent,
} from '@camada/core';
import iife from '@camada/browser/iife-string';
import { resolveEnv, type ResolvedEnv } from './env.js';
import {
  CHALLENGE_PATH, nodeChallengeKit, readBody, isHttps, writeChallengePage, writeChallengeJson,
} from './challenge.js';
import { SDK_ID } from './version.js';

const SESSION_COOKIE = '_sfp';   // same cookie as the edge collector: sid/ns comparable across taps
const SCRIPT_PATH = '/_cam/b.js';
const FP_PATH = '/_cam/fp';
const FP_MAX = 32 * 1024;   // matches the server's /fp cap: never accept what ingest will 413
const ATTACHED = Symbol.for('camada.attached');   // one wrap per server, however often attach() is called

export interface CamadaOptions {
  env?: Record<string, string | undefined>;
  fetchImpl?: typeof fetch;      // threaded into snapshot client, event queue, and the fp relay (tests)
  refreshMs?: number;
  scriptPath?: string;
  fpPath?: string;
  challenge?: boolean;           // enforce `challenge` verdicts with the first-party page (default true; CAMADA_CHALLENGE=0 also switches it off)
  challengePath?: string;        // where that page posts its solution (default /__camada/challenge)
  snapshotVersion?: SnapshotVersion;   // 5 (default) also carries the tenant's ordered custom rules; 4 the allow/challenge sides only; 3 opts out of both
}

interface CamadaRequest extends IncomingMessage {
  camada?: { rid: string; ip: string | null; sid: string };
  route?: { path?: string };     // Express fills this after routing
  camadaChallenged?: boolean;    // serveChallenge() already shipped this request's event
}

/** The getter `header` conditions read (§D3). node:http lower-cases every incoming name and
 *  the matcher always asks with a lower-cased one, so nothing has to be normalised here; a
 *  header the client repeated arrives as an array and is joined the way the wire carried it. */
const headerReader = (req: IncomingMessage) => (name: string): string | null => {
  const v = req.headers[name];
  return v == null ? null : Array.isArray(v) ? v.join(', ') : v;
};

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
  private readonly challengeOn: boolean;
  private readonly challengePath: string;
  private readonly kit: ChallengeKit | null = null;
  private readonly envSource: Record<string, string | undefined>;

  constructor(opts: CamadaOptions = {}) {
    this.envSource = opts.env ?? process.env;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.scriptPath = opts.scriptPath ?? SCRIPT_PATH;
    this.fpPath = opts.fpPath ?? FP_PATH;
    this.challengeOn = opts.challenge !== false && this.envSource.CAMADA_CHALLENGE !== '0';
    this.challengePath = opts.challengePath ?? CHALLENGE_PATH;
    this.env = resolveEnv(this.envSource);
    if (!this.env) return;                       // unconfigured: every entry point no-ops
    if (this.envSource.CAMADA_DISABLED === '1') return;   // killed at boot: no poll timer, no exit hooks, truly silent
    this.snap = new SnapshotClient({
      url: this.env.snapshotUrl, token: this.env.snapToken,
      mode: this.env.serverless ? 'lazy' : 'timer',
      refreshMs: opts.refreshMs, snapshotVersion: opts.snapshotVersion, fetchImpl: this.fetchImpl, sdk: SDK_ID,
    });
    this.queue = new EventQueue({ url: this.env.ingestUrl, token: this.env.ingestToken, fetchImpl: this.fetchImpl, sdk: SDK_ID });
    this.kit = nodeChallengeKit(this.env.secret);
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

    // enforce before anything else, beacon endpoints included — fail open while cold. The custom
    // rules read the user agent and the request headers (§D3); without them every `ua` and
    // `header` condition is false.
    const v = this.snap.verdict({ ip, path, ua: req.headers['user-agent'], header: headerReader(req) });
    if (v.block) {
      const headers: Record<string, string> = { 'x-block-reason': v.reason ?? '', 'x-block-version': v.version ?? '', 'content-type': 'text/plain' };
      if (v.rule) headers['x-block-rule'] = v.rule;   // a custom rule blocked: name it, so the customer knows which row to edit
      res.writeHead(403, headers);
      res.end('Forbidden');
      const ev = this.buildEvent(req, path, query, ip, { rid: randomUUID(), sid: null, newSession: false });
      ev.st = 403;   // blocked requests always ship: silent expiry makes blocks oscillate
      ev.blk = v.reason;   // SDK-01: the reason rides the event so the analyst counts SDK blocks, not the app's own 403s ('rule' when a rule decided)
      if (v.rule) ev.rl = v.rule;
      this.queue.push(ev);
      return true;
    }
    // `warn` passes the request and only marks its event (below, on response-finish); a skip
    // passes with nothing stamped at all — it is the absence of enforcement.

    // A challenge needs a resolved client IP: the nonce and the `_cch` cookie are bound to it,
    // so without one a single solve would mint a cookie every unidentified client could
    // present. No ip -> no challenge (fail open), the same stance ip rules take.
    if (this.challengeOn && this.kit && ip) {
      // The verify endpoint answers first: a challenged client must be able to reach it.
      if (req.method === 'POST' && path === this.challengePath) { this.verifyChallenge(req, res, ip); return true; }
      if (v.challenge && !this.challengePassed(req, ip)) { this.serveChallengeInner(req, res, ip, path + query); return true; }
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
      const https = (req.socket as { encrypted?: boolean }).encrypted || req.headers['x-forwarded-proto'] === 'https';
      res.setHeader('set-cookie', `${SESSION_COOKIE}=${sid}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax${https ? '; Secure' : ''}`);
    }
    req.camada = { rid, ip, sid };
    res.setHeader('x-rid', rid);

    const cfg = this.snap.config;
    const excluded = (cfg?.exclude || []).some((x) => path.startsWith(x));
    if (!excluded && Math.random() < (cfg?.sample ?? 1)) {
      res.on('finish', () => guarded(() => {
        // serveChallenge() may have answered from inside the app, and it already shipped the
        // `blk: "challenge"` row — one request, one event.
        if (req.camadaChallenged) return;
        const ev = this.buildEvent(req, path, query, ip, { rid, sid, newSession });
        ev.ts = t0;   // the request start: the timeline draws [ts, ts + dur]
        ev.st = res.statusCode;
        ev.dur = Date.now() - t0;
        if (req.route?.path) ev.rt = String(req.route.path);
        if (v.warn && v.rule) ev.wrn = v.rule;   // §D3: the warn rule that let this request through
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

  /** Reads the beacon POST (≤32 KB), answers 204 immediately, and queues the beacon as a `sig: 1`
   *  row with the trusted-proxy-resolved client IP: it rides the next event batch, so the analyst
   *  sees one request per flush instead of one per page view. Junk bodies are dropped, never shipped. */
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
      let parsed: unknown;
      try { parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { return; }
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return;
      this.queue!.push({ ...(parsed as Record<string, unknown>), sig: 1, ip, tap: TAP_NODE });
    }, undefined));
    req.on('error', () => { try { res.destroy(); } catch { /* already gone */ } });
  }

  private challengePassed(req: IncomingMessage, ip: string | null): boolean {
    return !!this.kit?.tokenValid(ip, Date.now(), cookieValue((req.headers.cookie as string) || '', CHALLENGE_COOKIE));
  }

  /** 403 + the proof-of-work page (HTML navigations) or 403 JSON (everything else), plus the
   *  `blk: "challenge"` event — a served challenge is reported like a block (contract §D2). */
  private serveChallengeInner(req: CamadaRequest, res: ServerResponse, ip: string, target: string): void {
    const to = safeReturnTo(target);
    if (wantsHtml((req.headers.accept as string) ?? null, (req.headers['sec-fetch-dest'] as string) ?? null)) {
      writeChallengePage(res, challengePage({ nonce: this.kit!.nonce(ip, Date.now()), action: this.challengePath, to }));
    } else {
      writeChallengeJson(res);
    }
    // The response is out; telemetry must never be able to undo that (a throw here would make
    // guarded() report the request as unhandled and let the app write to an ended response).
    guarded(() => {
      const qi = target.indexOf('?');
      const ev = this.buildEvent(req, qi === -1 ? target : target.slice(0, qi), qi === -1 ? '' : target.slice(qi), ip,
        { rid: randomUUID(), sid: this.sessionOf(req), newSession: false });
      ev.st = 403;
      ev.blk = 'challenge';
      this.queue!.push(ev);
    }, undefined);
  }

  /** The request's existing session, so challenge rows join the session that produced them. */
  private sessionOf(req: IncomingMessage): string | null {
    return cookieValue((req.headers.cookie as string) || '', SESSION_COOKIE);
  }

  /** POST from the challenge page: validate the nonce and the proof of work, set `_cch`, 302
   *  back to the (sanitised, same-site) original URL, and ship `{ st: 200, ch: 1 }`. */
  private verifyChallenge(req: CamadaRequest, res: ServerResponse, ip: string): void {
    readBody(req, (body) => guarded(() => {
      const form = parseFormBody(body);
      const to = safeReturnTo(form.to);
      const now = Date.now();
      if (!this.kit!.verify(ip, now, form.nonce, form.solution)) {
        writeChallengePage(res, challengePage({ nonce: this.kit!.nonce(ip, now), action: this.challengePath, to }));
        return;
      }
      res.writeHead(302, {
        location: to,
        'set-cookie': challengeCookie(this.kit!.issue(ip, now), isHttps(req)),
        'cache-control': 'no-store',
      });
      res.end();
      const ev = this.buildEvent(req, this.challengePath, '', ip, { rid: randomUUID(), sid: this.sessionOf(req), newSession: false });
      ev.st = 200;
      ev.ch = 1;   // challenge passed (contract §A3 ingest field)
      this.queue!.push(ev);
    }, undefined));
  }

  /**
   * Records the upgrades (WebSocket handshakes) a node:http or node:https server hands to its
   * 'upgrade' listeners: Node never routes those through the request handler the middleware runs
   * in. Each one ships one event with `st: 101` once the app's listeners have run. Observe only:
   * the request is never blocked or challenged, nothing is written to the socket, no session
   * cookie is minted, and a server with no 'upgrade' listener of its own behaves exactly as before
   * (this wraps `server.emit` rather than adding a listener, which would claim every upgrade).
   * Idempotent; returns the server. A handshake the WebSocket library then rejects still ships 101.
   */
  attach<S extends Server>(server: S): S {
    guarded(() => {
      const s = server as S & { [ATTACHED]?: true };
      if (this.disabled || !this.queue || s[ATTACHED]) return;
      s[ATTACHED] = true;
      const emit = s.emit.bind(s) as (event: string | symbol, ...args: unknown[]) => boolean;
      s.emit = ((event: string | symbol, ...args: unknown[]) => {
        if (event !== 'upgrade') return emit(event, ...args);
        const t0 = Date.now();
        try {
          return emit(event, ...args);
        } finally {
          guarded(() => this.shipUpgrade(args[0] as CamadaRequest, t0), undefined);
        }
      }) as S['emit'];
    }, undefined);
    return server;
  }

  private shipUpgrade(req: CamadaRequest, t0: number): void {
    if (this.disabled || !this.queue) return;
    const rawUrl = req.url || '/';
    const qi = rawUrl.indexOf('?');
    const path = qi === -1 ? rawUrl : rawUrl.slice(0, qi);
    const cfg = this.snap?.config;
    if ((cfg?.exclude || []).some((x) => path.startsWith(x)) || Math.random() >= (cfg?.sample ?? 1)) return;
    const ip = resolveClientIp(req.socket?.remoteAddress, req.headers['x-forwarded-for'] as string | undefined, this.trustedProxy());
    const ev = this.buildEvent(req, path, qi === -1 ? '' : rawUrl.slice(qi), ip, { rid: randomUUID(), sid: this.sessionOf(req), newSession: false });
    ev.ts = t0;
    ev.st = 101;
    ev.dur = Date.now() - t0;
    this.queue.push(ev);
  }

  /** Serve the challenge for this request on demand — for a route the app wants to gate itself
   *  (the example's /challenge-me). Returns false when the client already holds a valid `_cch`,
   *  so the caller renders its own page. */
  serveChallenge(req: IncomingMessage, res: ServerResponse): boolean {
    return guarded(() => {
      if (this.disabled || !this.kit || !this.queue) return false;
      const ip = resolveClientIp(req.socket?.remoteAddress, req.headers['x-forwarded-for'] as string | undefined, this.trustedProxy());
      if (!ip || this.challengePassed(req, ip)) return false;   // unidentifiable client: fail open
      (req as CamadaRequest).camadaChallenged = true;
      this.serveChallengeInner(req as CamadaRequest, res, ip, req.url || '/');
      return true;
    }, false);
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
        const uid = data?.user ? await hashUserId(data.user, this.env!.ingestToken, (globalThis.crypto ?? webcrypto).subtle) : null;
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
