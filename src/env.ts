// Environment wiring. The two-line quickstart depends on this file doing the right thing:
//   CAMADA_KEY=<ingest_token>.<snap_token>   (printed by `reconcile instructions` and seed)
//   CAMADA_INGEST_URL / CAMADA_SNAPSHOT_URL  (dev: http://localhost:8787[/snapshot])
//   CAMADA_DISABLED=1                        kill switch, checked per request
//   CAMADA_SERVERLESS=1                      lazy snapshot mode (no interval timer)
//   CAMADA_TRUSTED_PROXY                     local override: none | vercel | hops:N | cidrs:a,b
import { parseKey, type TrustedProxyConfig } from '@camada/core';

export interface ResolvedEnv {
  ingestToken: string;
  snapToken: string;
  ingestUrl: string;
  snapshotUrl: string;
  serverless: boolean;
  trustedProxy: TrustedProxyConfig | null;   // null = defer to server-delivered config
}

export function parseTrustedProxyEnv(v: string | undefined): TrustedProxyConfig | null {
  if (!v) return null;
  if (v === 'none') return { mode: 'none' };
  if (v === 'vercel') return { mode: 'vercel' };
  if (v.startsWith('hops:')) { const hops = Number(v.slice(5)); return Number.isInteger(hops) && hops >= 1 ? { mode: 'hops', hops } : null; }
  if (v.startsWith('cidrs:')) { const cidrs = v.slice(6).split(',').map((s) => s.trim()).filter(Boolean); return cidrs.length ? { mode: 'cidrs', cidrs } : null; }
  return null;
}

/** Returns null (SDK stays disabled, one log line) rather than throwing on bad config. */
export function resolveEnv(env: Record<string, string | undefined> = process.env): ResolvedEnv | null {
  const key = parseKey(env.CAMADA_KEY);
  const ingestToken = key?.ingestToken ?? env.CAMADA_TOKEN;
  const snapToken = key?.snapToken ?? env.CAMADA_SNAPSHOT_TOKEN;
  if (!ingestToken || !snapToken) return null;
  const ingestUrl = (env.CAMADA_INGEST_URL || 'https://in.camada.dev').replace(/\/$/, '');
  return {
    ingestToken, snapToken, ingestUrl,
    snapshotUrl: env.CAMADA_SNAPSHOT_URL || `${ingestUrl}/snapshot`,
    serverless: env.CAMADA_SERVERLESS === '1',
    trustedProxy: parseTrustedProxyEnv(env.CAMADA_TRUSTED_PROXY),
  };
}
