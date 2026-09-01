// Koa middleware over the raw req/res. Register first:
//   import { camadaKoa } from '@camada/node/koa';
//   app.use(camadaKoa());
import type { IncomingMessage, ServerResponse } from 'node:http';
import { Camada } from './camada.js';
import { getDefault } from './index.js';

interface KoaishCtx { req: IncomingMessage; res: ServerResponse; respond?: boolean }

export function camadaKoa(engine?: Camada) {
  return async (ctx: KoaishCtx, next: () => Promise<unknown>): Promise<void> => {
    if ((engine ?? getDefault()).handle(ctx.req, ctx.res)) { ctx.respond = false; return; }   // camada owns this response
    await next();
  };
}
