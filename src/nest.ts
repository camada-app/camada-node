// NestJS module (default Express platform). Import:
//   import { CamadaModule } from '@camada/node/nest';
//   @Module({ imports: [CamadaModule.forRoot()] })
// On the Fastify platform use the fastify plugin directly instead (see README).
import { Module, type DynamicModule, type MiddlewareConsumer, type NestModule } from '@nestjs/common';
import { Camada } from './camada.js';
import { getDefault } from './index.js';

let engine: Camada | null = null;
let routes = '{*splat}';   // Express 5 / Nest 11 catch-all incl. '/'; Nest ≤10 (Express 4) passes routes: '*'

@Module({})
export class CamadaModule implements NestModule {
  static forRoot(opts: { camada?: Camada; routes?: string } = {}): DynamicModule {
    engine = opts.camada ?? null;
    if (opts.routes) routes = opts.routes;
    return { module: CamadaModule };
  }
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply((engine ?? getDefault()).express()).forRoutes(routes);
  }
}
