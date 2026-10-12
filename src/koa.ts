// Koa middleware over the raw req/res. Register first:
//   import { camadaKoa } from '@camada/node/koa';
//   app.use(camadaKoa());
import type { IncomingMessage, ServerResponse } from 'node:http';
import { Camada } from './camada.js';
import { getDefault } from './index.js';

interface KoaishCtx {
  req: IncomingMessage & { body?: unknown; originalUrl?: string };
  res: ServerResponse;
  request?: { body?: unknown };
  originalUrl?: string;
  respond?: boolean;
}

export function camadaKoa(engine?: Camada) {
  return async (ctx: KoaishCtx, next: () => Promise<unknown>): Promise<void> => {
    // A body parser registered before camada (@koa/bodyparser, koa-bodyparser) leaves the form on
    // ctx.request.body, and koa-mount strips the mount from req.url: hand both to the engine.
    ctx.req.body ??= ctx.request?.body;
    ctx.req.originalUrl ??= ctx.originalUrl;
    if ((engine ?? getDefault()).handle(ctx.req, ctx.res)) { ctx.respond = false; return; }   // camada owns this response
    await next();
  };
}
