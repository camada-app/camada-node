// The engine: node:http-level request handling every adapter delegates to.
//   camada.handle(req, res) -> true when camada fully answered the request (block or beacon
//   endpoint), false when the app should proceed. Everything runs inside the fail-open
//   envelope: a camada bug must never 5xx the customer (plan.md INT-2), and CAMADA_DISABLED=1
//   bypasses the SDK entirely.
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { randomUUID, webcrypto } from 'node:crypto';   // webcrypto handed to hashUserId explicitly, so the hash never depends on which global the host exposes
import {
  SnapshotClient, EventQueue, buildWireEvent, resolveClientIp, hashUserId, guarded, logRateLimited,
  challengeCookie, safeReturnTo, wantsHtml, CHALLENGE_COOKIE,
  TAP_NODE, type ChallengeKit, type SnapshotVersion, type TrustedProxyConfig, type WireEvent,
} from '@camada/core';
import iife from '@camada/browser/iife-string';
import { resolveEnv, type ResolvedEnv } from './env.js';
import {
  CHALLENGE_PATH, nodeChallengeKit, readForm, parsedBody, isHttps, writeChallengePage, writeChallengeJson,
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
  /** With CAMADA_SERVERLESS=1: handed every per-request event flush and snapshot refresh, so the
   *  platform keeps the invocation alive until they finish (e.g. `waitUntil` from `@vercel/functions`). */
  waitUntil?: (p: Promise<unknown>) => void;
}

interface CamadaRequest extends IncomingMessage {
  originalUrl?: string;          // Express/Nest: the full URL; `url` loses the mount path inside app.use('/x', …)
  body?: unknown;                // what a body parser mounted before camada left behind
  camada?: { rid: string; ip: string | null; sid: string };
  route?: { path?: string };     // Express fills this after routing
  camadaChallenged?: boolean;    // serveChallenge() already shipped this request's event
  camadaOpen?: boolean;          // its event ships on response finish: a track() row until then rides that flush
  camadaTracks?: Promise<void>[];   // track() rows still hashing (serverless: the finish flush waits for them)
  camadaPrefix?: string;         // the mount prefix seen when camada ran (scriptTag() runs later, where req.url is whole again)
}

/** The getter `header` conditions read (§D3). node:http lower-cases every incoming name and
 *  the matcher always asks with a lower-cased one, so nothing has to be normalised here; a
 *  header the client repeated arrives as an array and is joined the way the wire carried it. */
const headerReader = (req: IncomingMessage) => (name: string): string | null => {
  const v = req.headers[name];
  return v == null ? null : Array.isArray(v) ? v.join(', ') : v;
};

const splitUrl = (raw: string): { path: string; query: string } => {
  const qi = raw.indexOf('?');
  return qi === -1 ? { path: raw, query: '' } : { path: raw.slice(0, qi), query: raw.slice(qi) };
};

/** Path and query as the client sent them: what rules, the challenge list and events see. Express
 *  strips the mount path from `req.url` inside `app.use(path, mw)` (Nest mounts module middleware
 *  that way, at '{*splat}' or '*'), and koa-mount does the same (the Koa adapter copies Koa's
 *  `originalUrl` over), so read `originalUrl` first; plain node:http and Fastify only have `url`. */
function pathAndQuery(req: CamadaRequest): { path: string; query: string } {
  return splitUrl(req.originalUrl || req.url || '/');
}

/** Whether the request is for one of camada's own endpoints (beacon script, beacon POST,
 *  challenge verify). Those answer at the mount-relative path (`req.url`), so `app.use('/api',
 *  camada)` serves `/api/_cam/b.js`, and at the full path, so a wildcard mount (Nest, whose
 *  `req.url` is stripped to '/') still serves `/_cam/b.js`. */
const atEndpoint = (req: CamadaRequest, path: string, endpoint: string): boolean =>
  path === endpoint || splitUrl(req.url || '/').path === endpoint;

/** The mount prefix camada runs under: the full path minus the mount-relative one, when the full
 *  path ends with it (`app.use('/api', …)`, koa-mount). A relative path of `/` says nothing: it is
 *  both the mount's own root and what a wildcard mount (Nest) strips every path to, so no prefix. */
function mountPrefix(req: CamadaRequest): string {
  if (!req.originalUrl) return '';
  const full = splitUrl(req.originalUrl).path, rel = splitUrl(req.url || '/').path;
  return rel !== '/' && full !== rel && full.endsWith(rel) ? full.slice(0, full.length - rel.length) : '';
}

/** A unix-socket (pipe) listener: Node never has a peer address there, on any request. The
 *  listening server reports its address as the socket path (a string); `_pipeName` keeps the
 *  answer after server.close() has dropped the handle while connections drain. */
function onUnixListener(socket: unknown): boolean {
  const srv = (socket as { server?: { address?: () => unknown; _pipeName?: unknown } } | null)?.server;
  if (!srv) return false;
  try { if (typeof srv.address?.() === 'string') return true; } catch { /* not a net.Server */ }
  return typeof srv._pipeName === 'string';
}

const cookieValue = (cookie: string, name: string): string | null => {
  const src = '; ' + cookie;
  const i = src.indexOf('; ' + name + '=');
  if (i === -1) return null;
  const start = i + name.length + 3;
  const j = src.indexOf(';', start);
  return src.slice(start, j === -1 ? undefined : j);
};

/** Sets a first visit's `_sfp` and keeps it there: an app that replaces Set-Cookie through
 *  setHeader (or writeHead, setHeaders, which route through it once any header is set) gets its
 *  own cookies plus the session's, unless it set `_sfp` itself. appendHeader already keeps it. */
function keepSessionCookie(res: ServerResponse, cookie: string): void {
  const set = res.setHeader;
  res.setHeader = function (this: ServerResponse, name: string, value: number | string | readonly string[]) {
    if (typeof name === 'string' && name.toLowerCase() === 'set-cookie') {
      const list = Array.isArray(value) ? value : [String(value)];
      if (!list.some((c) => String(c).trimStart().startsWith(SESSION_COOKIE + '='))) value = [...list, cookie];
    }
    return set.call(this, name, value);
  } as ServerResponse['setHeader'];
  res.setHeader('set-cookie', cookie);
}

export class Camada {
  readonly env: ResolvedEnv | null;
  readonly snap: SnapshotClient | null = null;
  readonly queue: EventQueue | null = null;
  private readonly fetchImpl: typeof fetch;
  private readonly scriptPath: string;
  private readonly fpPath: string;
  private readonly challengeOn: boolean;
  private readonly challengePath: string;
  private readonly challengePathSet: boolean;   // configured explicitly: used as given, never prefixed
  private readonly scriptPathSet: boolean;
  private readonly kit: ChallengeKit | null = null;
  private readonly envSource: Record<string, string | undefined>;
  private readonly waitUntil?: (p: Promise<unknown>) => void;

  constructor(opts: CamadaOptions = {}) {
    this.envSource = opts.env ?? process.env;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.waitUntil = opts.waitUntil;
    this.scriptPath = opts.scriptPath ?? SCRIPT_PATH;
    this.fpPath = opts.fpPath ?? FP_PATH;
    this.challengeOn = opts.challenge !== false && this.envSource.CAMADA_CHALLENGE !== '0';
    this.challengePath = opts.challengePath ?? CHALLENGE_PATH;
    this.challengePathSet = opts.challengePath != null;
    this.scriptPathSet = opts.scriptPath != null;
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

  /** The client IP per the trusted-proxy config (team contract C6 v3). No socket at all, or a
   *  unix-socket listener (nginx/Passenger in front, where Node never has a peer): core's no-peer
   *  X-Forwarded-For walk, which trusts the local proxy. A TCP socket with no readable peer (the
   *  client reset the connection before camada ran, e.g. behind an async middleware) is
   *  unidentifiable: the walk would believe whatever the client wrote. So: null, the stance every
   *  ip-bound feature already takes (no ip rules, no challenge). */
  private clientIp(req: IncomingMessage): string | null {
    const peer = req.socket?.remoteAddress;
    if (!peer && req.socket && !onUnixListener(req.socket)) return null;
    return resolveClientIp(peer ?? null, req.headers['x-forwarded-for'] as string | undefined, this.trustedProxy());
  }

  /** Where the challenge form posts: under the mount prefix, so it reaches camada, unless the
   *  path was configured explicitly. */
  private challengeAction(req: CamadaRequest): string {
    return this.challengePathSet ? this.challengePath : (req.camadaPrefix ?? mountPrefix(req)) + this.challengePath;
  }

  private beaconEnabled(): boolean { return this.snap?.config?.beacon !== false; }

  /** Queues a row. With CAMADA_SERVERLESS=1 it also starts the POST now: the platform freezes the
   *  process once the response is out, so the 15 s interval would never run. Never throws. */
  private enqueue(row: unknown, req?: CamadaRequest): void {
    const q = this.queue!;
    q.push(row);
    if (!this.env?.serverless) return;
    if (req?.camadaOpen) return;   // a track() row while the response is open: the finish flush carries it
    this.flushFor(req);
  }

  /** Serverless: start the POST now and hand it to waitUntil. Never throws. */
  private flushFor(req?: CamadaRequest): void {
    const q = this.queue!;
    guarded(() => {
      // One POST per request: the response-finish flush first waits for that request's track()
      // rows still hashing. flush() is single-in-flight, so a row queued while a POST was
      // finishing rides a second one.
      const tracks = req?.camadaTracks ?? [];
      const p = Promise.allSettled(tracks)
        .then(() => q.flush())
        .then(() => (q.size > 0 ? q.flush() : undefined));
      this.waitUntil?.(p);
    }, undefined);
  }

  /** True when camada fully handled the request. Synchronous; never throws. */
  handle(req: IncomingMessage, res: ServerResponse): boolean {
    return guarded(() => this.handleInner(req as CamadaRequest, res), false);
  }

  private handleInner(req: CamadaRequest, res: ServerResponse): boolean {
    if (this.disabled || !this.snap || !this.queue || !this.env) return false;
    const t0 = Date.now();
    this.snap.ensureFresh(this.env.serverless ? this.waitUntil : undefined);

    const { path, query } = pathAndQuery(req);
    const ip = this.clientIp(req);
    req.camadaPrefix = mountPrefix(req);

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
      this.enqueue(ev);
      return true;
    }
    // `warn` passes the request and only marks its event (below, on response-finish); a skip
    // passes with nothing stamped at all — it is the absence of enforcement.

    // A challenge needs a resolved client IP: the nonce and the `_cch` cookie are bound to it,
    // so without one a single solve would mint a cookie every unidentified client could
    // present. No ip -> no challenge (fail open), the same stance ip rules take.
    if (this.challengeOn && this.kit && ip) {
      // The verify endpoint answers first: a challenged client must be able to reach it.
      if (req.method === 'POST' && atEndpoint(req, path, this.challengePath)) { this.verifyChallenge(req, res, ip); return true; }
      if (v.challenge && !this.challengePassed(req, ip)) { this.serveChallengeInner(req, res, ip, path + query); return true; }
    }

    if (this.beaconEnabled()) {
      if (req.method === 'GET' && atEndpoint(req, path, this.scriptPath)) {
        res.writeHead(200, { 'content-type': 'application/javascript', 'cache-control': 'public, max-age=3600' });
        res.end(iife);
        return true;
      }
      if (req.method === 'POST' && atEndpoint(req, path, this.fpPath)) {
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
      keepSessionCookie(res, `${SESSION_COOKIE}=${sid}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax${https ? '; Secure' : ''}`);
    }
    req.camada = { rid, ip, sid };
    res.setHeader('x-rid', rid);

    const cfg = this.snap.config;
    const excluded = (cfg?.exclude || []).some((x) => path.startsWith(x));
    if (!excluded && Math.random() < (cfg?.sample ?? 1)) {
      // 'finish' when the response went out whole; 'close' alone when the client left first (an
      // aborted SSE or download), which ships the status set so far and dur up to the abort — the
      // fetch adapters' cancel semantics. 'close' also follows every 'finish': one event either way.
      let shipped = false;
      req.camadaOpen = true;
      const ship = () => guarded(() => {
        req.camadaOpen = false;
        if (shipped) return;
        shipped = true;
        // serveChallenge() may have answered from inside the app, and it already shipped the
        // `blk: "challenge"` row — one request, one event. A track() row queued while the
        // response was open still needs this finish flush (serverless).
        if (req.camadaChallenged) { if (this.env?.serverless) this.flushFor(req); return; }
        const ev = this.buildEvent(req, path, query, ip, { rid, sid, newSession });
        ev.ts = t0;   // the request start: the timeline draws [ts, ts + dur]
        ev.st = res.statusCode;
        ev.dur = Date.now() - t0;
        if (req.route?.path) ev.rt = String(req.route.path);
        if (v.warn && v.rule) ev.wrn = v.rule;   // §D3: the warn rule that let this request through
        this.enqueue(ev, req);
      }, undefined);
      res.once('finish', ship);
      res.once('close', ship);
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
   *  sees one request per flush instead of one per page view. Junk bodies are dropped, never shipped.
   *  A body parser mounted before camada (express.json(), always on Nest) has already drained the
   *  stream: its `req.body` is used instead, and the request is answered either way. */
  private relayBeacon(req: CamadaRequest, res: ServerResponse, ip: string | null): void {
    const accept = (parsed: unknown) => {
      res.writeHead(204, { 'cache-control': 'no-store' });
      res.end();
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || Buffer.isBuffer(parsed)) return;
      this.enqueue({ ...(parsed as Record<string, unknown>), sig: 1, ip, tap: TAP_NODE });
    };
    const fromText = (text: string) => { try { return JSON.parse(text) as unknown; } catch { return null; } };
    if (req.readableEnded) {
      const b = parsedBody(req);
      if ((typeof b === 'string' ? b : b ? JSON.stringify(b) : '').length > FP_MAX) { res.writeHead(413).end(); return; }
      accept(typeof b === 'string' ? fromText(b) : b);
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0, dead = false;
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > FP_MAX) { dead = true; req.removeAllListeners('data'); res.writeHead(413).end(); return; }
      chunks.push(c);
    });
    req.on('end', () => guarded(() => {
      if (dead) return;
      accept(fromText(Buffer.concat(chunks).toString('utf8')));
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
      writeChallengePage(res, { nonce: this.kit!.nonce(ip, Date.now()), action: this.challengeAction(req), to });
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
      this.enqueue(ev);
    }, undefined);
  }

  /** The request's existing session, so challenge rows join the session that produced them. */
  private sessionOf(req: IncomingMessage): string | null {
    return cookieValue((req.headers.cookie as string) || '', SESSION_COOKIE);
  }

  /** POST from the challenge page: validate the nonce and the proof of work, set `_cch`, 302
   *  back to the (sanitised, same-site) original URL, and ship `{ st: 200, ch: 1 }`. */
  private verifyChallenge(req: CamadaRequest, res: ServerResponse, ip: string): void {
    readForm(req, (form) => guarded(() => {
      const to = safeReturnTo(form.to);
      const now = Date.now();
      if (!this.kit!.verify(ip, now, form.nonce, form.solution)) {
        writeChallengePage(res, { nonce: this.kit!.nonce(ip, now), action: this.challengeAction(req), to });
        return;
      }
      res.writeHead(302, {
        location: to,
        'set-cookie': challengeCookie(this.kit!.issue(ip, now), isHttps(req)),
        'cache-control': 'no-store',
      });
      res.end();
      const ev = this.buildEvent(req, this.challengeAction(req), '', ip, { rid: randomUUID(), sid: this.sessionOf(req), newSession: false });
      ev.st = 200;
      ev.ch = 1;   // challenge passed (contract §A3 ingest field)
      this.enqueue(ev);
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
    const { path, query } = pathAndQuery(req);
    const cfg = this.snap?.config;
    if ((cfg?.exclude || []).some((x) => path.startsWith(x)) || Math.random() >= (cfg?.sample ?? 1)) return;
    const ip = this.clientIp(req);
    const ev = this.buildEvent(req, path, query, ip, { rid: randomUUID(), sid: this.sessionOf(req), newSession: false });
    ev.ts = t0;
    ev.st = 101;
    ev.dur = Date.now() - t0;
    this.enqueue(ev);
  }

  /** Serve the challenge for this request on demand — for a route the app wants to gate itself
   *  (the example's /challenge-me). Returns false when the client already holds a valid `_cch`,
   *  so the caller renders its own page. */
  serveChallenge(req: IncomingMessage, res: ServerResponse): boolean {
    return guarded(() => {
      if (this.disabled || !this.kit || !this.queue) return false;
      const ip = this.clientIp(req);
      if (!ip || this.challengePassed(req, ip)) return false;   // unidentifiable client: fail open
      (req as CamadaRequest).camadaChallenged = true;
      const { path, query } = pathAndQuery(req as CamadaRequest);
      this.serveChallengeInner(req as CamadaRequest, res, ip, path + query);
      return true;
    }, false);
  }

  /** For HTML templates: the first-party beacon tag with the request's rid. */
  scriptTag(req: IncomingMessage): string {
    if (this.disabled || !this.beaconEnabled()) return '';
    const rid = (req as CamadaRequest).camada?.rid;
    const r = req as CamadaRequest;
    const src = this.scriptPathSet ? this.scriptPath : (r.camadaPrefix ?? mountPrefix(r)) + this.scriptPath;
    return `<script src="${src}${rid ? `?r=${rid}` : ''}" async></script>`;
  }

  /** App-context outcome events (login failed, signup, …). The identifier is HMAC-hashed
   *  in-process; the raw value never reaches the queue. */
  track(req: IncomingMessage, event: string, data?: { user?: string }): void {
    guarded(() => {
      if (this.disabled || !this.queue || !this.env) return;
      const ctx = (req as CamadaRequest).camada;
      const r = req as CamadaRequest;
      const row = (async () => {
        const uid = data?.user ? await hashUserId(data.user, this.env!.ingestToken, (globalThis.crypto ?? webcrypto).subtle) : null;
        this.enqueue({ tap: TAP_NODE, et: event, uid, rid: ctx?.rid ?? null, sid: ctx?.sid ?? null, ip: ctx?.ip ?? null, ts: Date.now() }, r);
      })().catch(logRateLimited);
      if (r.camadaOpen) (r.camadaTracks ??= []).push(row);
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
