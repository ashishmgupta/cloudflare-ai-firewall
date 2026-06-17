import { z } from 'zod';

// Free-form classification schema for Layer 3 model output.
// The model classifies content using a fixed taxonomy; downstream code
// matches these classifications to the configured policy structure.

export const L3ClassificationSchema = z.object({
  category: z.string(),
  subcategory: z.string().default(''),
  severity: z.enum(['high', 'medium', 'low']).default('medium'),
  confidence: z.number().min(0).max(1).default(0.8),
  evidence: z.string().max(200).default(''),
});

export const L3ModelOutputSchema = z.object({
  reasoning: z.string().optional(),
  verdict: z.enum(['pass', 'block', 'monitor']),
  classifications: z.array(L3ClassificationSchema),
});

export type L3Classification = z.infer<typeof L3ClassificationSchema>;
export type L3ModelOutput = z.infer<typeof L3ModelOutputSchema>;
