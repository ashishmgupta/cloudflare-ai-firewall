import { z } from 'zod';
import type {
  VerdictSchema,
  LayerSourceSchema,
  MitreAtlasSchema,
  ViolationSchema,
  InspectRequestSchema,
  InspectResponseSchema,
  PolicySchema,
  ApiKeyRecordSchema,
  TenantSchema,
  AuditEventSchema,
} from './schemas.js';

export type Verdict = z.infer<typeof VerdictSchema>;
export type LayerSource = z.infer<typeof LayerSourceSchema>;
export type MitreAtlasTechnique = z.infer<typeof MitreAtlasSchema>;
export type Violation = z.infer<typeof ViolationSchema>;
export type InspectRequest = z.infer<typeof InspectRequestSchema>;
export type InspectResponse = z.infer<typeof InspectResponseSchema>;
export type Policy = z.infer<typeof PolicySchema>;
export type ApiKeyRecord = z.infer<typeof ApiKeyRecordSchema>;
export type Tenant = z.infer<typeof TenantSchema>;
export type AuditEvent = z.infer<typeof AuditEventSchema>;
