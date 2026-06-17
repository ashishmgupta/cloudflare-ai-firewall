export interface Env {
  AI: Ai;
  POLICY_CACHE: KVNamespace;   // securityProfile:{keyHash} → {profileId} AND securityProfile:{profileId} → document
  VERDICT_CACHE: KVNamespace;  // verdict:{cacheKey} → InspectResponse
  FIREWALL_VECTORIZE?: VectorizeIndex;
  ENVIRONMENT: string;
  ADMIN_TOKEN: string;         // allows tester to inspect any profile via X-Admin-Token + X-Profile-Id
}
