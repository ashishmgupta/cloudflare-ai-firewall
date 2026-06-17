export interface Env {
  AI: Ai;
  POLICY_CACHE: KVNamespace;   // securityProfile:{keyHash} → {profileId} AND securityProfile:{profileId} → document
  VERDICT_CACHE: KVNamespace;  // verdict:{cacheKey} → InspectResponse
  FIREWALL_VECTORIZE?: VectorizeIndex;
  EVENTS_DB?: D1Database;
  ENVIRONMENT: string;
}
