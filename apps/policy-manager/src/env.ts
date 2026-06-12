export interface Env {
  AI: Ai;
  POLICY_CACHE: KVNamespace;
  API_KEYS: KVNamespace;
  TENANTS: KVNamespace;
  POLICY_STORE: R2Bucket;
  AUDIT_LOG: R2Bucket;
  FIREWALL_VECTORIZE: VectorizeIndex;
  ADMIN_TOKEN: string;
  ENVIRONMENT: string;
}
