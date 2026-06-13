export interface Env {
  AI: Ai;
  POLICY_CACHE: KVNamespace;   // securityProfile:{keyHash} → {profileId} AND securityProfile:{profileId} → document
  VERDICT_CACHE: KVNamespace;  // verdict:{cacheKey} → InspectResponse
  FIREWALL_VECTORIZE?: VectorizeIndex;
  RATE_LIMITER: DurableObjectNamespace;
  KEY_REVOCATION: DurableObjectNamespace;
  ENVIRONMENT: string;
}
