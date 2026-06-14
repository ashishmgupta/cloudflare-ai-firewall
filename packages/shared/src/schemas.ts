import { z } from 'zod';

// ─── MITRE ATLAS ──────────────────────────────────────────────────────────────

export const MitreAtlasSchema = z.object({
  techniqueId: z.string(),
  techniqueName: z.string(),
  tactic: z.string(),
});

// ─── Setting (toggleable sub-entity of a Detection) ───────────────────────────

export const SettingSchema = z.object({
  id: z.string(),
  name: z.string().min(1),
  enabled: z.boolean().default(true),
  description: z.string().default(''),
});

// ─── Custom pattern (word/phrase or regex, for user-defined rules) ────────────

export const CustomPatternSchema = z.object({
  value: z.string().min(1),
  isRegex: z.boolean().default(false),
  description: z.string().default(''),
});

// ─── Detection (enforcement unit) ────────────────────────────────────────────

export const DetectionSchema = z.object({
  id: z.string(),
  name: z.string().min(1),
  description: z.string().default(''),
  mode: z.enum(['block', 'monitor']),
  threshold: z.number().min(0).max(1).optional(),
  settings: z.array(SettingSchema).default([]),
  detectionExample: z.string().default(''),
  safeExample: z.string().default(''),
  mitreAtlas: MitreAtlasSchema.optional(),
  type: z.enum(['builtin', 'custom']).default('builtin'),
  customPatterns: z.array(CustomPatternSchema).default([]),
});

// ─── Category (grouping of detections) ────────────────────────────────────────

export const CategorySchema = z.object({
  id: z.string(),
  name: z.string().min(1),
  description: z.string().default(''),
  detections: z.array(DetectionSchema).default([]),
});

// ─── SecurityPolicy (embedded in profile — no sharing, no cross-references) ───

export const SecurityPolicySchema = z.object({
  id: z.string(),
  name: z.string().min(1),
  description: z.string().default(''),
  categories: z.array(CategorySchema).default([]),
});

// ─── SecurityProfile (top-level document, self-contained) ─────────────────────

export const SecurityProfileSchema = z.object({
  id: z.string(),
  name: z.string().min(1).max(128),
  description: z.string().default(''),
  policies: z.array(SecurityPolicySchema).default([]),
  failOpen: z.boolean().default(true),
  cacheTtlSeconds: z.number().int().positive().default(3600),
  createdAt: z.string(),
  updatedAt: z.string(),
});

// ─── API Key Record ───────────────────────────────────────────────────────────

export const ApiKeyRecordSchema = z.object({
  id: z.string(),
  name: z.string().min(1),
  keyHash: z.string(),
  profileId: z.string(),
  active: z.boolean().default(true),
  createdAt: z.string(),
  revokedAt: z.string().nullable().default(null),
});

// ─── Violation (normalized — identical shape from all layers) ─────────────────

export const DetectedBySchema = z.enum(['heuristic', 'vector', 'llm', 'cache']);

export const ViolationSchema = z.object({
  policyName: z.string(),
  categoryName: z.string(),
  detectionName: z.string(),
  setting: z.string(),
  mode: z.enum(['block', 'monitor']),
  confidence: z.number().min(0).max(1),
  detectedBy: DetectedBySchema,
  evidence: z.string(),
  mitreAtlas: MitreAtlasSchema,
});

// ─── Verdict ──────────────────────────────────────────────────────────────────

// block > monitor > pass  (block beats monitor beats pass, score-free)
export const VerdictSchema = z.enum(['pass', 'block', 'monitor']);

// ─── Inspect request / response ───────────────────────────────────────────────

export const InspectRequestSchema = z.object({
  prompt: z.string().min(1),
  context: z.array(z.string()).optional(),
  metadata: z.record(z.unknown()).optional(),
});

export const InspectResponseSchema = z.object({
  requestId: z.string(),
  verdict: VerdictSchema,
  profile: z.object({ id: z.string(), name: z.string() }),
  violations: z.array(ViolationSchema),
  cached: z.boolean(),
  // latencyMs is intentionally absent from the body — use response headers instead:
  //   X-Firewall-Latency-Ms  total wall-clock for THIS request (accurate even for cache hits)
  //   X-Firewall-Layer{n}-Ms per-layer breakdown (omitted on cache hits — those layers didn't run)
  // Kept optional below only so old KV-cached blobs (which still carry latencyMs) parse cleanly.
  latencyMs: z.object({ total: z.number(), perLayer: z.record(z.number()) }).optional(),
});

// ─── CRUD schemas (policy-manager) ───────────────────────────────────────────

export const CreateProfileSchema = SecurityProfileSchema.omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const UpdateProfileSchema = CreateProfileSchema.partial();

export const CreateApiKeySchema = z.object({
  name: z.string().min(1).max(128),
  profileId: z.string().min(1),
});

// ─── Audit log ────────────────────────────────────────────────────────────────

export const AuditEventSchema = z.object({
  id: z.string(),
  action: z.string(),
  resourceType: z.string(),
  resourceId: z.string(),
  before: z.unknown().nullable(),
  after: z.unknown().nullable(),
  timestamp: z.string(),
});
