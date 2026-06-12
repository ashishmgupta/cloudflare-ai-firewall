import { z } from 'zod';

// ─── Core types ───────────────────────────────────────────────────────────────

export const VerdictSchema = z.enum(['pass', 'flag', 'block']);

export const LayerSourceSchema = z.enum(['heuristic', 'vector', 'llm']);

export const MitreAtlasSchema = z.object({
  techniqueId: z.string(),
  techniqueName: z.string(),
  tactic: z.string(),
});

export const ViolationSchema = z.object({
  category: z.string(),
  categoryName: z.string(),
  layer: LayerSourceSchema,
  confidence: z.number().min(0).max(1),
  mitreAtlas: MitreAtlasSchema,
});

// ─── Inspect request / response ───────────────────────────────────────────────

export const InspectRequestSchema = z.object({
  prompt: z.string().min(1),
  context: z.array(z.string()).optional(),
  metadata: z.record(z.unknown()).optional(),
  mode: z.enum(['sync', 'async']).default('sync'),
});

export const InspectResponseSchema = z.object({
  requestId: z.string(),
  verdict: VerdictSchema,
  score: z.number().min(0).max(100),
  policy: z.object({ id: z.string(), name: z.string() }),
  violations: z.array(ViolationSchema),
  latencyMs: z.object({
    total: z.number(),
    perLayer: z.record(z.number()),
  }),
  cached: z.boolean(),
});

export const AsyncInspectResponseSchema = z.object({
  requestId: z.string(),
  status: z.literal('queued'),
});

// ─── Policy ───────────────────────────────────────────────────────────────────

export const PolicyLayerConfigSchema = z.object({
  enabled: z.boolean().default(true),
});

export const Layer1ConfigSchema = PolicyLayerConfigSchema.extend({
  ttlSeconds: z.number().int().positive().default(3600),
});

export const Layer2ConfigSchema = PolicyLayerConfigSchema.extend({
  similarityThreshold: z.number().min(0).max(1).default(0.85),
});

export const CategoryActionSchema = z.enum(['pass', 'flag', 'block']);

export const PolicySchema = z.object({
  id: z.string(),
  name: z.string().min(1).max(128),
  description: z.string().default(''),
  tenantId: z.string(),
  layers: z.object({
    layer0: PolicyLayerConfigSchema.default({ enabled: true }),
    layer1: Layer1ConfigSchema.default({ enabled: true, ttlSeconds: 3600 }),
    layer2: Layer2ConfigSchema.default({ enabled: true, similarityThreshold: 0.85 }),
    layer3: PolicyLayerConfigSchema.default({ enabled: true }),
  }),
  categoryActions: z.record(CategoryActionSchema).default({}),
  scoreThresholds: z
    .object({ flag: z.number().default(50), block: z.number().default(75) })
    .default({ flag: 50, block: 75 }),
  failOpen: z.boolean().default(true),
  rateLimit: z
    .object({
      requestsPerMinute: z.number().int().positive(),
      requestsPerHour: z.number().int().positive(),
    })
    .nullable()
    .default(null),
  webhookUrl: z.string().url().nullable().default(null),
  mitreAtlasMappings: z.record(MitreAtlasSchema).default({}),
  createdAt: z.string(),
  updatedAt: z.string(),
});

// ─── API Key ──────────────────────────────────────────────────────────────────

export const ApiKeyRecordSchema = z.object({
  id: z.string(),
  keyHash: z.string(),
  tenantId: z.string(),
  name: z.string(),
  policyIds: z.array(z.string()),
  defaultPolicyId: z.string(),
  active: z.boolean().default(true),
  createdAt: z.string(),
  lastUsedAt: z.string().nullable().default(null),
});

// ─── Tenant ───────────────────────────────────────────────────────────────────

export const TenantSchema = z.object({
  id: z.string(),
  name: z.string().min(1).max(128),
  email: z.string().email(),
  active: z.boolean().default(true),
  createdAt: z.string(),
});

// ─── Policy Manager request schemas ──────────────────────────────────────────

export const CreateTenantSchema = TenantSchema.omit({ id: true, createdAt: true });

export const CreatePolicySchema = PolicySchema.omit({
  id: true,
  tenantId: true,
  createdAt: true,
  updatedAt: true,
});

export const UpdatePolicySchema = CreatePolicySchema.partial();

export const CreateApiKeySchema = z.object({
  name: z.string().min(1).max(128),
  tenantId: z.string().min(1),
  policyIds: z.array(z.string()).min(1),
  defaultPolicyId: z.string().min(1),
});

export const AddSignatureSchema = z.object({
  text: z.string().min(1),
  category: z.string().min(1),
  description: z.string().default(''),
  mitreAtlasId: z.string().default('AML.T0051'),
});

// ─── Audit log ────────────────────────────────────────────────────────────────

export const AuditEventSchema = z.object({
  id: z.string(),
  actor: z.string(),
  action: z.string(),
  resourceType: z.string(),
  resourceId: z.string(),
  before: z.unknown().nullable(),
  after: z.unknown().nullable(),
  timestamp: z.string(),
});
