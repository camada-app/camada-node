// One smoke test per adapter: blocked IP -> 403 before the app; normal request -> app response
// with x-rid. Real framework instances, real sockets.
import { describe, it, expect, afterEach } from 'vitest';
import { fakeAnalyst, engineWith, loaded, BLOCKED_IP } from './harness.js';
import { camadaFastify } from '../src/fastify.js';
import { camadaKoa } from '../src/koa.js';

const closers: Array<() => Promise<unknown> | unknown> = [];
afterEach(async () => { for (const c of closers.splice(0)) await c(); });

async function ready() {
  const a = fakeAnalyst();
  const engine = engineWith(a, { CAMADA_TRUSTED_PROXY: 'hops:1' });
  closers.push(() => engine.stop());
  await loaded(engine);
  return { a, engine };
}

const hit = async (port: number, blocked = false) =>
  fetch(`http://127.0.0.1:${port}/`, blocked ? { headers: { 'x-forwarded-for': BLOCKED_IP } } : undefined);

describe('adapters', () => {
  it('express', async () => {
    const { engine } = await ready();
    const { default: express } = await import('express');
    const app = express();
    app.use(engine.express());
    app.get('/', (_req, res) => { res.send('ok'); });
    const server = await new Promise<import('node:http').Server>((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
    closers.push(() => new Promise((r) => server.close(r)));
    const port = (server.address() as { port: number }).port;
    expect((await hit(port, true)).status).toBe(403);
    const ok = await hit(port);
    expect(ok.status).toBe(200);
    expect(ok.headers.get('x-rid')).toBeTruthy();
  });

  it('fastify', async () => {
    const { engine } = await ready();
    const { default: Fastify } = await import('fastify');
    const app = Fastify();
    await app.register(camadaFastify as never, { camada: engine } as never);
    app.get('/', async () => 'ok');
    await app.listen({ port: 0, host: '127.0.0.1' });
    closers.push(() => app.close());
    const port = (app.server.address() as { port: number }).port;
    expect((await hit(port, true)).status).toBe(403);
    const ok = await hit(port);
    expect(ok.status).toBe(200);
    expect(ok.headers.get('x-rid')).toBeTruthy();
  });

  it('koa', async () => {
    const { engine } = await ready();
    const { default: Koa } = await import('koa');
    const app = new Koa();
    app.use(camadaKoa(engine));
    app.use(async (ctx) => { ctx.body = 'ok'; });
    const server = await new Promise<import('node:http').Server>((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
    closers.push(() => new Promise((r) => server.close(r)));
    const port = (server.address() as { port: number }).port;
    expect((await hit(port, true)).status).toBe(403);
    const ok = await hit(port);
    expect(ok.status).toBe(200);
    expect(ok.headers.get('x-rid')).toBeTruthy();
  });

  it('nest (express platform)', async () => {
    const { engine } = await ready();
    await import('reflect-metadata');
    const { CamadaModule } = await import('../src/nest.js');
    const { Module, Controller, Get } = await import('@nestjs/common');
    const { NestFactory } = await import('@nestjs/core');

    @Controller()
    class RootController {
      @Get() root() { return 'ok'; }
    }
    @Module({ imports: [CamadaModule.forRoot({ camada: engine })], controllers: [RootController] })
    class AppModule {}

    const app = await NestFactory.create(AppModule, { logger: false });
    await app.listen(0, '127.0.0.1');
    closers.push(() => app.close());
    const port = (app.getHttpServer().address() as { port: number }).port;
    expect((await hit(port, true)).status).toBe(403);
    const ok = await hit(port);
    expect(ok.status).toBe(200);
    expect(ok.headers.get('x-rid')).toBeTruthy();
  });
});
