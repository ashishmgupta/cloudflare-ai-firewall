import { z } from 'zod';
import type {
  MitreAtlasSchema,
  SettingSchema,
  DetectionSchema,
  CategorySchema,
  SecurityPolicySchema,
  SecurityProfileSchema,
  ApiKeyRecordSchema,
  ViolationSchema,
  VerdictSchema,
  DetectedBySchema,
  MessageSchema,
  InspectRequestSchema,
  InspectResponseSchema,
  AuditEventSchema,
} from './schemas.js';

export type MitreAtlasTechnique = z.infer<typeof MitreAtlasSchema>;
export type Setting = z.infer<typeof SettingSchema>;
export type Detection = z.infer<typeof DetectionSchema>;
export type Category = z.infer<typeof CategorySchema>;
export type SecurityPolicy = z.infer<typeof SecurityPolicySchema>;
export type SecurityProfile = z.infer<typeof SecurityProfileSchema>;
export type ApiKeyRecord = z.infer<typeof ApiKeyRecordSchema>;
export type Violation = z.infer<typeof ViolationSchema>;
export type Verdict = z.infer<typeof VerdictSchema>;
export type DetectedBy = z.infer<typeof DetectedBySchema>;
export type Message = z.infer<typeof MessageSchema>;
export type InspectRequest = z.infer<typeof InspectRequestSchema>;
export type InspectResponse = z.infer<typeof InspectResponseSchema>;
export type AuditEvent = z.infer<typeof AuditEventSchema>;
