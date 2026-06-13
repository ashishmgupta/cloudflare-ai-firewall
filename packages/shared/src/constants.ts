export const MAX_PROMPT_BYTES = 32 * 1024;
export const PROFILE_MEMORY_CACHE_TTL_MS = 60_000;
export const DEFAULT_CACHE_TTL_SECONDS = 3600;
export const GLOBAL_RPM_CAP = 60;

// Both key→profileId and profileId→document use this prefix (≤2 KV reads per request)
export const KV_PROFILE_PREFIX = 'securityProfile:';

export const R2_PREFIX = {
  PROFILES: 'profiles/',
  APIKEYS: 'apikeys/',
  AUDIT: 'audit/',
  SIGNATURES: 'signatures/',
} as const;

export const ERROR_CODES = {
  INVALID_API_KEY: 'INVALID_API_KEY',
  RATE_LIMITED: 'RATE_LIMITED',
  PROFILE_NOT_FOUND: 'PROFILE_NOT_FOUND',
  PROMPT_TOO_LARGE: 'PROMPT_TOO_LARGE',
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  UPSTREAM_ERROR: 'UPSTREAM_ERROR',
  INTERNAL_ERROR: 'INTERNAL_ERROR',
} as const;
