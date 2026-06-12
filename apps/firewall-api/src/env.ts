export interface Env {
  AI: Ai;
  POLICY_CACHE: KVNamespace;
  VERDICT_CACHE: KVNamespace;
  API_KEYS: KVNamespace;
  FIREWALL_VECTORIZE?: VectorizeIndex;
  RATE_LIMITER: DurableObjectNamespace;
  KEY_REVOCATION: DurableObjectNamespace;
  ANALYTICS?: AnalyticsEngineDataset;
  ENVIRONMENT: string;
}
