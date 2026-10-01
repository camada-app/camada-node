# @camada/node

camada's backend SDK for Node: captures request metadata on response-finish (real status,
latency, and the true wire header order no proxy position can see), enforces the tenant
blocklist inline before your app runs, and serves the fingerprint beacon first-party at
`/_cam/b.js` + `/_cam/fp`. Fails open by design: a camada outage or bug never 5xxes your app.

Not yet on npm — consumed via `file:` dependency from a sibling checkout.

## Quickstart

Env (printed by camada onboarding / `npm run seed` in dev):

```
CAMADA_KEY=<ingest_token>.<snap_token>
CAMADA_INGEST_URL=http://localhost:8787        # dev only; defaults to production ingest
```

**Express / Connect**
```js
import camada from '@camada/node';
app.use(camada.express());
```

**Fastify**
```js
import { camadaFastify } from '@camada/node/fastify';
await app.register(camadaFastify);
```

**NestJS** (default Express platform; on the Fastify platform register the fastify plugin instead)
```ts
import { CamadaModule } from '@camada/node/nest';
@Module({ imports: [CamadaModule.forRoot()] })   // Nest ≤10: CamadaModule.forRoot({ routes: '*' })
```

**Koa**
```js
import { camadaKoa } from '@camada/node/koa';
app.use(camadaKoa());
```

## What it does per request

1. Refreshes the blocklist snapshot off-path (30 s poll, ETag; cold start fails open). Every
   poll and event batch carries `x-camada-sdk: @camada/node/<version>`.
2. Resolves the client IP per your tenant's trusted-proxy config — raw `X-Forwarded-For` is
   never trusted without it (`CAMADA_TRUSTED_PROXY=hops:1|cidrs:…|vercel` overrides locally).
3. Runs your ordered custom rules (see below), then the allow, block and challenge lists.
   Blocked → `403` with `x-block-reason` before your app; the event still ships, with
   `st: 403` and `blk: <reason>` (ip4|ip6|path|rule) so the analyst counts SDK blocks apart
   from your app's own 403s.
4. Serves `/_cam/b.js` (the beacon, first-party — no third-party domain for ad-blockers or CSP
   to break) and relays `/_cam/fp` posts to ingest with the resolved client IP.
5. Otherwise: sets `x-rid` + the `_sfp` session cookie, and on response-finish ships one
   batched, redacted event (Authorization/Cookie values never leave the process; credential-
   looking query values are scrubbed; see @camada/core).

## Custom rules

Your Rules page holds one ordered list per project, and this SDK walks it before the allow,
block and challenge lists. First match wins — the order *is* the precedence — and each rule
carries one of four actions:

| action | what this SDK does | on the event |
|---|---|---|
| `skip` | passes the request | nothing |
| `block` | `403` before your app | `blk: "rule"`, `rl: "<rule id>"` |
| `challenge` | serves the proof-of-work page (`challenge: false` opts out) | `blk: "challenge"` |
| `warn` | passes the request and marks it for the analyst | `wrn: "<rule id>"` |

A skip rule also carries a *record matches* flag, which only the analyst reads: a recorded skip
is still scored and shows on your dashboard as Allowed, an unrecorded one is dropped before
scoring. Either way the request passes here, unstamped — the built-in Allow-list is a skip rule
with recording on.

A rule block also names the row that decided, so the response says which rule to edit:

```
HTTP/1.1 403 Forbidden
x-block-reason: rule
x-block-rule: cr_4f2a9c1b7e03
```

A rule may also test one request header (`is`, `contains` or `matches`), and the header name is
matched case-insensitively against what the client actually sent. Headers belong to the request
plane alone: the analyst never sees them, so it treats a header rule as not matching and only a
v5 SDK like this one enforces it.

The rules ride the v5 snapshot, which this SDK asks for by default. `snapshotVersion: 4`
pins the allow/challenge lists without the rules, `3` the block list alone; a project that
has not published the container you ask for is answered with the next one down, so asking
for the newest is always safe.

HTML templates add the beacon with the helper (or use `@camada/react`'s `<CamadaBeacon/>`):

```js
res.send(`<head>${camada.scriptTag(req)}</head>…`);
```

App-context outcomes (the signals no edge tap can see; identifiers are HMAC-hashed in-process):

```js
camada.track(req, 'login_failed', { user: email });
```

The event name is free-form, but the analyst's app-context rules read a fixed vocabulary — use these names
and the credential-stuffing, password-spray, account-aggregation, signup-velocity, carding and coupon rules
fire on your app's own truth instead of path heuristics:

| event | when |
|---|---|
| `login_failed` / `login_succeeded` | a password (or passwordless) login attempt settled; pass `{ user }` so attempts per account can be counted |
| `signup` | an account was created |
| `password_reset` | a reset was requested |
| `mfa_failed` | a second factor was rejected |
| `payment_failed` / `payment_succeeded` | a payment authorisation settled |
| `coupon_failed` | a promo/voucher code was rejected |

## WebSockets

Node hands an upgrade request (a WebSocket handshake) to the server's `'upgrade'` listeners,
never to the request handler the middleware runs in, so the middleware alone never sees one.
Pass the server to `attach()` and each upgrade ships one event with `st: 101`:

```js
const server = app.listen(3000);            // Fastify: app.server · Nest: app.getHttpServer() · Koa: app.listen()
camada.attach(server);                      // returns the server; calling it twice is harmless
new WebSocketServer({ server });            // ws, socket.io, … attach before or after, either way
```

It only observes. The handshake stays your WebSocket library's: camada writes nothing to the
socket, adds no delay, sets no session cookie (the event carries the visitor's existing `_sfp`),
and never blocks or challenges an upgrade. A server with no `'upgrade'` listener of its own
behaves exactly as before. The event is recorded when Node hands the upgrade over, so a
handshake your library then rejects still ships `st: 101`.

## Operational notes

- `CAMADA_DISABLED=1` — kill switch, checked per request.
- `CAMADA_SERVERLESS=1` — lazy snapshot refresh (no interval timer); cold invocations fail
  open and catch up asynchronously.
- Enforcement scope at this position: IP, path, user-agent and request-header conditions. ASN,
  country and TLS-fingerprint conditions can't be evaluated in-app and fail open (a rule that
  needs one never matches here; run `@camada/hono` on Cloudflare Workers for those).
- Memory: ~5 MB per loaded snapshot.

## Develop

```
npm install && npm run build && npm test && npm run check
```
Sibling checkouts of `camada-core` and `camada-browser` must exist (file: deps).
