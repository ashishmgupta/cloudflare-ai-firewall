export interface Env {
  AI: Ai;
  POLICY_CACHE: KVNamespace;   // securityProfile:{keyHash} and securityProfile:{profileId}
  POLICY_STORE: R2Bucket;      // profiles/{id}.json, apikeys/{hash}.json, signatures/{id}.json
  AUDIT_LOG: R2Bucket;
  FIREWALL_VECTORIZE?: VectorizeIndex;
  DB: D1Database;
  ENVIRONMENT: string;
}
