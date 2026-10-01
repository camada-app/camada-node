// Environment wiring. The two-line quickstart depends on this file doing the right thing:
//   CAMADA_KEY=<ingest_token>.<snap_token>   (printed by `reconcile instructions` and seed)
//   CAMADA_INGEST_URL / CAMADA_SNAPSHOT_URL  (dev: http://localhost:8787[/snapshot])
//   CAMADA_DISABLED=1                        kill switch, checked per request
//   CAMADA_SERVERLESS=1                      lazy snapshot mode (no interval timer)
//   CAMADA_TRUSTED_PROXY                     local override: none | vercel | hops:N | cidrs:a,b
import { parseKey, parseTrustedProxyEnv, type TrustedProxyConfig } from '@camada/core';

export { parseTrustedProxyEnv };   // re-export: this was @camada/node's public surface before it moved to core

export interface ResolvedEnv {
  ingestToken: string;
  snapToken: string;
  secret: string;                            // HMAC key for the challenge nonce/cookie — never leaves the process
  ingestUrl: string;
  snapshotUrl: string;
  serverless: boolean;
  trustedProxy: TrustedProxyConfig | null;   // null = defer to server-delivered config
}

/** Returns null (SDK stays disabled, one log line) rather than throwing on bad config. */
export function resolveEnv(env: Record<string, string | undefined> = process.env): ResolvedEnv | null {
  const key = parseKey(env.CAMADA_KEY);
  const ingestToken = key?.ingestToken ?? env.CAMADA_TOKEN;
  const snapToken = key?.snapToken ?? env.CAMADA_SNAPSHOT_TOKEN;
  if (!ingestToken || !snapToken) return null;
  const ingestUrl = (env.CAMADA_INGEST_URL || 'https://in.camada.app').replace(/\/$/, '');
  return {
    ingestToken, snapToken, ingestUrl,
    secret: env.CAMADA_KEY || `${ingestToken}.${snapToken}`,
    snapshotUrl: env.CAMADA_SNAPSHOT_URL || `${ingestUrl}/snapshot`,
    serverless: env.CAMADA_SERVERLESS === '1',
    trustedProxy: parseTrustedProxyEnv(env.CAMADA_TRUSTED_PROXY),
  };
}
