// Fastify plugin, dependency-free (no fastify-plugin needed): the skip-override symbol keeps
// the hook on the parent scope. Register:
//   import { camadaFastify } from '@camada/node/fastify';
//   await app.register(camadaFastify);
import type { IncomingMessage, ServerResponse } from 'node:http';
import { Camada } from './camada.js';
import { getDefault } from './index.js';

interface Fastifyish {
  addHook(name: 'onRequest', hook: (request: { raw: IncomingMessage }, reply: { raw: ServerResponse; hijack(): void }, done: () => void) => void): void;
}

export function camadaFastify(instance: Fastifyish, opts: { camada?: Camada }, done: (err?: Error) => void): void {
  const engine = opts.camada ?? getDefault();
  instance.addHook('onRequest', (request, reply, hookDone) => {
    if (engine.handle(request.raw, reply.raw)) reply.hijack();   // camada wrote the response on the raw socket
    hookDone();
  });
  done();
}
(camadaFastify as unknown as Record<symbol, boolean>)[Symbol.for('skip-override')] = true;
