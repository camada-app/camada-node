# Changelog

## Unreleased

Needs `@camada/core` with `challengePageCsp` (next release after 0.5.1).

### Fixed

- Block responses (path, ip, asn, country, tls and rule blocks, the `Forbidden` 403) now send `cache-control: no-store`, like the challenge answers, so a shared cache cannot serve one visitor's block to others. An upstream `cache-control` set on `res` is replaced. (camada-all-8lp6)
- NestJS: every request was seen as `/`. Path rules and the path side of the challenge list did
  nothing, `/_cam/b.js`, `/_cam/fp` and `/__camada/challenge` fell through to Nest's 404, and every
  event shipped `p: "/"`. Express strips the mount path from `req.url` inside `app.use(path, …)`,
  which is how Nest mounts module middleware. camada now reads `req.originalUrl` first, which
  also fixes prefix mounts in plain Express (camada-all-6ogs).
- The challenge verify POST and the beacon POST hung until the server timeout when a body parser
  ran before camada (always on Nest). camada now uses the parser's `req.body`, and answers at once
  when the body was read and nothing usable is left (camada-all-r3s6).
- `CAMADA_SERVERLESS=1` flushes each request's event and every `track()` row as they are queued,
  instead of waiting for the 15 s timer a frozen function never runs (camada-all-fcc3).
- The challenge page works under the app's CSP (helmet before camada). It sends its own
  `Content-Security-Policy` that allows only its inline script and style by hash, and drops any
  inherited `Content-Security-Policy` / `Content-Security-Policy-Report-Only` (camada-all-mwpo).

- A client that reset its connection before camada ran (behind an async middleware) left no
  readable peer address, and the trusted-proxy walk then believed its `X-Forwarded-For`, so a
  spoofed address could evade a block or frame someone else. When the request has a socket but
  no peer, camada now resolves no IP, which is the same as any unidentifiable client: no ip rules
  and no challenge (camada-all-yfc6).
- On a unix-socket listener (nginx or Passenger in front of Node) every request has no peer
  address, and the fix above gave every one of them no IP, even with a trusted proxy configured.
  A unix-socket listener now runs the trusted-proxy walk without a peer, trusting the local proxy;
  only a TCP request whose peer is gone resolves no IP (camada-all-yfc6).
- Under a prefix mount (`app.use('/api', …)`, koa-mount) the challenge form posted to
  `/__camada/challenge` at the root, which never reached camada, so no browser could pass the
  challenge; `scriptTag()` pointed at the root too. Both now point under the mount prefix, unless
  `challengePath` / `scriptPath` were set explicitly (camada-all-6ogs).
- `CAMADA_SERVERLESS=1`: a `track()` row queued before `serveChallenge()` answered the request is
  flushed when the response finishes, instead of waiting in the queue (camada-all-fcc3).
- Koa: behind `@koa/bodyparser` / `koa-bodyparser`, challenge verification failed every time
  and beacons were dropped. The adapter now hands `ctx.request.body` to the engine
  (camada-all-r3s6).
- The challenge page's CSP is computed for the page's own `bits`.
- The challenge page's CSP no longer sets `form-action`. Browsers also apply it to the redirects
  after the verify POST, so an app that sent the browser on to an external sign-in was blocked
  (through `@camada/core`, camada-all-mwpo).

### Changed

- `Camada.stop()` returns `Promise<void>` (was `void`): it settles once rows still queued behind a
  drain in flight or an ingest 429 hold are sent or counted dropped, so a graceful shutdown can
  `await camada.stop()` before exiting. Calling it without `await` works as before. (camada-all-a4m9)
- camada's own endpoints (`/_cam/b.js`, `/_cam/fp`, `/__camada/challenge`) answer at the
  mount-relative path as well as the full path. `app.use('/api', camada.express())` serves them
  under `/api` again, as it did before the `originalUrl` change above, while rules and events keep
  the full path (camada-all-6ogs).
- Koa under `koa-mount`: rules and events now see the full path (`/api/…`), not the
  mount-stripped one. The adapter copies Koa's `ctx.originalUrl` to the request (camada-all-6ogs).
- The `exports` map now gives `require` its own `.d.cts` declarations (`import` and `require` each carry a `types` condition), so a CommonJS TypeScript app on `moduleResolution: node16` compiles; CI runs `@arethetypeswrong/cli`. (camada-all-vuzm)

### Added

- `createCamada({ waitUntil })`: with `CAMADA_SERVERLESS=1`, every per-request flush and lazy
  snapshot refresh is handed to it so the platform keeps the invocation alive (camada-all-fcc3).

## 0.3.1 (2026-10-09; follows 0.3.0)

Needs `@camada/core` 0.5.1.

### Fixed

- The snapshot client no longer re-polls back to back when `/snapshot` fails. It keeps its blocks and
  waits max(`retry-after`, 5 s), capped at the refresh interval (through `@camada/core` 0.5.1,
  camada-all-pbv9).

## 0.3.0 (2026-10-04; follows 0.2.0)

### Changed

- `engines.node` is `>=20` (was `>=18`). npm only warns on an older Node unless `engine-strict`
  is set.
- The default ingest is `https://in.camada.app` (was `https://in.camada.dev`). `in.camada.dev`
  still answers as an alias, so apps on 0.2.0 keep shipping. `CAMADA_INGEST_URL` still overrides
  it.
- `ts` is the request start, so `[ts, ts + dur]` is when the request ran. It used to be stamped at
  response finish, which drew every request one `dur` late.
- `dur` is unchanged: request start to response finish, the whole body included. A client that
  disconnects first now ships too (see Fixed).

### Added

- `camada.attach(server)` records WebSocket upgrades. Node sends an upgrade to the server's
  `'upgrade'` event and never runs the middleware, so upgrades shipped nothing. After `attach`,
  each one ships an event with `st: 101` and the visitor's existing `_sfp`, once your own
  `'upgrade'` listeners have run. It writes nothing to the socket, sets no cookie and is safe to
  call twice.

### Fixed

- Path rules match the canonical path (through `@camada/core` 0.5.0). A percent-encoded,
  upper-cased or trailing-slash spelling of a blocked path used to slip past the block.
- A first visit keeps its `_sfp` session cookie when the app sets its own cookies with
  `res.setHeader('set-cookie', …)` or `res.writeHead(…, { 'set-cookie': … })`. Express
  `res.cookie()` already worked.
- A request whose client disconnects mid-response (an aborted SSE stream or download) ships its
  event, with the status set so far and `dur` up to the disconnect. It used to leave no row.
