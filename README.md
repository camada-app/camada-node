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
3. Blocked ip/path → `403` with `x-block-reason` before your app; the event still ships,
   with `st: 403` and `blk: <reason>` (ip4|ip6|path) so the analyst counts SDK blocks apart
   from your app's own 403s.
4. Serves `/_cam/b.js` (the beacon, first-party — no third-party domain for ad-blockers or CSP
   to break) and relays `/_cam/fp` posts to ingest with the resolved client IP.
5. Otherwise: sets `x-rid` + the `_sfp` session cookie, and on response-finish ships one
   batched, redacted event (Authorization/Cookie values never leave the process; credential-
   looking query values are scrubbed; see @camada/core).

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

## Operational notes

- `CAMADA_DISABLED=1` — kill switch, checked per request.
- `CAMADA_SERVERLESS=1` — lazy snapshot refresh (no interval timer); cold invocations fail
  open and catch up asynchronously.
- Enforcement scope at this position: IP and path entries. ASN/TLS-fingerprint entries can't
  be evaluated in-app and fail open.
- Memory: ~5 MB per loaded snapshot.

## Develop

```
npm install && npm run build && npm test && npm run check
```
Sibling checkouts of `camada-core` and `camada-browser` must exist (file: deps).
