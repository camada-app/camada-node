// Quickstart (Express / Connect / Nest-on-Express):
//   import camada from '@camada/node';
//   app.use(camada.express());        // env: CAMADA_KEY (+ CAMADA_INGEST_URL for dev)
// The default export is a lazy singleton wired from the environment on first use.
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { Camada, createCamada, type CamadaOptions } from './camada.js';

export { Camada, createCamada, type CamadaOptions } from './camada.js';
export { resolveEnv, parseTrustedProxyEnv, type ResolvedEnv } from './env.js';

let singleton: Camada | null = null;
export function getDefault(): Camada {
  return (singleton ??= createCamada());
}
/** Test/reset hook: replaces the singleton (stops the old one). */
export function configure(opts: CamadaOptions): Camada {
  singleton?.stop();
  singleton = createCamada(opts);
  return singleton;
}

export default {
  express: () => (req: IncomingMessage, res: ServerResponse, next: (err?: unknown) => void) => { if (!getDefault().handle(req, res)) next(); },
  handle: (req: IncomingMessage, res: ServerResponse) => getDefault().handle(req, res),
  scriptTag: (req: IncomingMessage) => getDefault().scriptTag(req),
  serveChallenge: (req: IncomingMessage, res: ServerResponse) => getDefault().serveChallenge(req, res),
  track: (req: IncomingMessage, event: string, data?: { user?: string }) => getDefault().track(req, event, data),
  attach: <S extends Server>(server: S): S => getDefault().attach(server),
  configure,
};
