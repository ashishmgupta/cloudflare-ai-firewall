import { z } from 'zod';

// Single source of truth for the Layer 3 model contract.
// The schema description is embedded verbatim into the system prompt;
// the Zod schema parses and validates the model's raw JSON response.

export const ModelViolationSchema = z.object({
  policyName: z.string(),
  categoryName: z.string(),
  detectionName: z.string(),
  setting: z.string(),
  mode: z.enum(['block', 'monitor']),
  confidence: z.number().min(0).max(1).default(0.8),
  evidence: z.string().max(200).default(''),
});

export const ModelOutputSchema = z.object({
  verdict: z.enum(['pass', 'block', 'monitor']),
  violations: z.array(ModelViolationSchema),
});

export type ModelViolation = z.infer<typeof ModelViolationSchema>;
export type ModelOutput = z.infer<typeof ModelOutputSchema>;

export const MODEL_OUTPUT_SCHEMA_DESCRIPTION = `{
  "verdict": "pass" | "block" | "monitor",
  "violations": [
    {
      "policyName": "<exact policy name from the active profile>",
      "categoryName": "<exact category name from the active profile>",
      "detectionName": "<exact detection name from the active profile>",
      "setting": "<exact enabled setting name that triggered, or repeat detectionName if no sub-settings>",
      "mode": "<exact mode for that detection: block or monitor>",
      "confidence": <0.0 to 1.0>,
      "evidence": "<short excerpt ≤100 chars that triggered — never the full prompt>"
    }
  ]
}`;
