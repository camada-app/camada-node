# Changelog

## 0.3.0 (unreleased; follows 0.2.0)

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

- A first visit keeps its `_sfp` session cookie when the app sets its own cookies with
  `res.setHeader('set-cookie', …)` or `res.writeHead(…, { 'set-cookie': … })`. Express
  `res.cookie()` already worked.
- A request whose client disconnects mid-response (an aborted SSE stream or download) ships its
  event, with the status set so far and `dur` up to the disconnect. It used to leave no row.
