import { MODEL_OUTPUT_SCHEMA_DESCRIPTION, ModelOutputSchema } from '@firewall/shared';
import type { Violation } from '@firewall/shared';
import type { Env } from '../env.js';
import type { ActiveDetection } from './layer0-heuristics.js';

function buildSystemPrompt(activeDetections: ActiveDetection[]): string {
  const detectionLines = activeDetections.map(ad => {
    const settingsText = ad.enabledSettings.length > 0
      ? ad.enabledSettings.map(s => `  - ${s.name}: ${s.description || s.name}`).join('\n')
      : '  (all behaviors within this detection)';
    return `Policy: ${ad.policyName}
  Category: ${ad.categoryName}
  Detection: ${ad.detection.name} [mode: ${ad.detection.mode}]
  Enabled settings:
${settingsText}`;
  }).join('\n\n');

  return `You are a security content classifier. Analyze the user message against the active detection profile below.

## Active Detection Profile

${detectionLines}

## Required Output Format

Respond ONLY with a JSON object — no markdown fences, no prose before or after:

${MODEL_OUTPUT_SCHEMA_DESCRIPTION}

## Classification Rules

- Only report violations for detections and settings listed in the Active Detection Profile above.
- Do NOT flag strong opinions, criticism, satire, or fiction without clear harmful intent.
- "setting" must exactly match an enabled setting name listed above.
- "mode" must exactly match the mode listed for that detection.
- "evidence" is a short excerpt ≤100 chars — never reproduce the full message.
- Return empty violations array with "verdict":"pass" if nothing triggers.`;
}

export async function checkLayer3Llm(
  prompt: string,
  activeDetections: ActiveDetection[],
  env: Env,
): Promise<Violation[]> {
  const systemPrompt = buildSystemPrompt(activeDetections);

  console.log('[layer3] calling llama-3.1-8b-instruct, detections:', activeDetections.length);

  const result = await env.AI.run('@cf/meta/llama-3.1-8b-instruct', {
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: prompt },
    ],
    max_tokens: 512,
  }) as { response: string };

  const raw = (result.response ?? '').trim();
  console.log('[layer3] raw response:', raw.slice(0, 300));

  // Strip markdown fences if the model adds them despite instructions
  const jsonStr = raw.replace(/^```(?:json)?\s*/i, '').replace(/\s*```\s*$/, '').trim();

  let parsed;
  try {
    parsed = ModelOutputSchema.parse(JSON.parse(jsonStr));
  } catch (err) {
    console.error('[layer3] parse error:', err);
    return [];
  }

  const violations: Violation[] = [];
  for (const mv of parsed.violations) {
    const ad = activeDetections.find(
      a => a.detection.name === mv.detectionName && a.policyName === mv.policyName,
    );
    if (!ad) continue; // model hallucinated a non-existent detection — discard

    violations.push({
      policyName: mv.policyName,
      categoryName: mv.categoryName,
      detectionName: mv.detectionName,
      setting: mv.setting,
      mode: mv.mode,
      confidence: mv.confidence,
      detectedBy: 'llm',
      evidence: mv.evidence,
      mitreAtlas: ad.detection.mitreAtlas,
    });
  }

  return violations;
}
