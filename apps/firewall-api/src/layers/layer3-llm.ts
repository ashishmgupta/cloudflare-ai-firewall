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
- Return empty violations array with "verdict":"pass" if nothing triggers.

## Explicit Exclusions for Content Moderation

Content Moderation covers harmful CONTENT categories only: violence, explicit sexual content, hate speech, illegal activity promotion, harassment, and self-harm. It does NOT cover data handling concerns.

Do NOT flag the following under Content Moderation — they are handled by Sensitive Data policies, not here:
- API keys, API tokens, API secrets, access tokens, auth tokens, bearer tokens
- Passwords, passphrases, credentials, or private keys
- Secret values with vendor prefixes (e.g. sk-, ghp_, AKIA, xoxb-, AIza, pk_live_)
- Any request that embeds credentials in order to authenticate to a service

If the prompt contains a credential but no actual harmful content, return "verdict":"pass" with no violations.`;
}

export async function checkLayer3Llm(
  prompt: string,
  activeDetections: ActiveDetection[],
  env: Env,
): Promise<Violation[]> {
  const systemPrompt = buildSystemPrompt(activeDetections);

  console.log('[layer3] ── SYSTEM PROMPT ──────────────────────────────────────');
  console.log(systemPrompt);
  console.log('[layer3] ── USER PROMPT ────────────────────────────────────────');
  console.log(prompt.slice(0, 200));
  console.log('[layer3] ────────────────────────────────────────────────────────');

  const result = await env.AI.run('@cf/meta/llama-3.3-70b-instruct-fp8-fast', {
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: prompt },
    ],
    max_tokens: 512,
  }) as Record<string, unknown>;

  const r = result as Record<string, unknown>;
  console.log('[layer3] result type:', typeof r, 'keys:', Object.keys(r ?? {}));

  // llama-3.3-70b-instruct-fp8-fast returns { response: <object>, tool_calls, usage }
  // where response is already the parsed JSON — pass it directly to Zod.
  // Older models return { response: <string> } or a bare string — parse those.
  let jsonToParse: unknown;
  if (r?.response !== null && typeof r?.response === 'object') {
    jsonToParse = r.response;
  } else {
    const raw = (
      typeof r === 'string' ? r as unknown as string :
      typeof r?.response === 'string' ? r.response as string :
      typeof r?.text === 'string' ? r.text as string :
      JSON.stringify(r)
    ).trim();
    console.log('[layer3] raw response:', raw.slice(0, 300));
    const jsonStr = raw.replace(/^```(?:json)?\s*/i, '').replace(/\s*```\s*$/, '').trim();
    jsonToParse = JSON.parse(jsonStr);
  }
  console.log('[layer3] jsonToParse:', JSON.stringify(jsonToParse).slice(0, 300));

  let parsed;
  try {
    parsed = ModelOutputSchema.parse(jsonToParse);
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
