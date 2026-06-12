export const MAX_PROMPT_BYTES = 32 * 1024;
export const DEFAULT_CACHE_TTL_SECONDS = 3600;
export const POLICY_MEMORY_CACHE_TTL_MS = 60_000;
export const DEFAULT_VECTOR_SIMILARITY_THRESHOLD = 0.85;
export const DEFAULT_FLAG_SCORE = 50;
export const DEFAULT_BLOCK_SCORE = 75;
export const DEFAULT_RATE_LIMIT_RPM = 60;
export const DEFAULT_RATE_LIMIT_RPH = 1000;

export const KV_PREFIX = {
  POLICY: 'policy:',
  API_KEY: 'apikey:',
  TENANT: 'tenant:',
  VERDICT: 'verdict:',
} as const;

export const R2_PREFIX = {
  POLICY: 'policies/',
  AUDIT: 'audit/',
  SIGNATURES: 'signatures/',
} as const;

export const ERROR_CODES = {
  INVALID_API_KEY: 'INVALID_API_KEY',
  RATE_LIMITED: 'RATE_LIMITED',
  POLICY_NOT_FOUND: 'POLICY_NOT_FOUND',
  PROMPT_TOO_LARGE: 'PROMPT_TOO_LARGE',
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  UPSTREAM_ERROR: 'UPSTREAM_ERROR',
  INTERNAL_ERROR: 'INTERNAL_ERROR',
} as const;
