import { defineConfig } from 'tsup';
export default defineConfig({ entry: ['src/index.ts', 'src/fastify.ts', 'src/nest.ts', 'src/koa.ts'], format: ['esm', 'cjs'], dts: true, sourcemap: true, clean: true, external: ['@camada/core', '@camada/browser', '@nestjs/common'] });
