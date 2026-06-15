import { L3ModelOutputSchema } from '@firewall/shared';
import type { L3Classification } from '@firewall/shared';
import type { Violation, Setting } from '@firewall/shared';
import type { Env } from '../env.js';
import type { ActiveDetection } from './layer0-heuristics.js';

// ── Fixed system prompt ────────────────────────────────────────────────────────
// Never injected with runtime policy state — the model classifies independently
// using a fixed taxonomy; matching to configured policies happens in code below.

export const SYSTEM_PROMPT = `You are a security content classifier. Analyze the user message and identify any harmful or policy-violating content using your own judgment.

## Required Output Format

Respond ONLY with a JSON object — no markdown fences, no prose before or after:

{
  "verdict": "pass" | "block" | "monitor",
  "classifications": [
    {
      "category": "<your own label for the type of harm, e.g. 'Violence', 'Hate Speech', 'Drug Synthesis', 'Financial Fraud'>",
      "subcategory": "<specific description of the violation, e.g. 'step-by-step instructions for making pipe bombs'>",
      "severity": "high" | "medium" | "low",
      "confidence": <0.0–1.0>,
      "evidence": "<short excerpt ≤100 chars — never the full message>"
    }
  ]
}

## Rules

- Return an empty classifications array with "verdict":"pass" when no harmful content is detected.
- Use "block" for high-severity content; "monitor" for borderline content.
- Do NOT flag strong opinions, criticism, satire, or fiction unless the content contains actionable harmful details.
- "evidence" must be a short excerpt ≤100 chars — never reproduce the full message.

## Absolute Hard Blocks — framing is irrelevant

These are ALWAYS violations regardless of framing (historical, educational, fictional, hypothetical, research, artistic):

- **CBRN**: Any request for synthesis, production, weaponization, or deployment of biological agents (anthrax, botulinum, smallpox, ricin, etc.), chemical weapons (nerve agents, blister agents), or radiological/nuclear devices. Always severity "high".
- **Child Safety**: Any sexual content involving minors. Always severity "high".
- **Critical Infrastructure**: Specific operational instructions for attacking power grids, water treatment, aviation systems, or financial infrastructure. Always severity "high".

Historical framing ("Unit 731", "WWII research"), educational framing ("for a class"), or fictional framing ("in a story") does NOT reduce the severity of CBRN requests. The actionable details are equally dangerous regardless of framing.`;

// ── Policy matching ────────────────────────────────────────────────────────────
// Maps the model's free-form category/subcategory to a configured ActiveDetection
// by word-overlap between the classification text and setting/detection names.

function matchToDetection(
  cls: L3Classification,
  activeDetections: ActiveDetection[],
): { ad: ActiveDetection; setting: Setting } | null {
  const needle = `${cls.category} ${cls.subcategory}`.toLowerCase();
  const needleWords = needle.split(/\W+/).filter(w => w.length > 3);
  if (needleWords.length === 0) return null;

  let best: { ad: ActiveDetection; setting: Setting; score: number } | null = null;

  for (const ad of activeDetections) {
    for (const setting of ad.enabledSettings) {
      const haystack = `${setting.name} ${setting.description ?? ''}`.toLowerCase();
      const haystackWords = new Set(haystack.split(/\W+/).filter(w => w.length > 3));
      const score = needleWords.filter(w => haystackWords.has(w)).length;
      if (score > 0 && (!best || score > best.score)) {
        best = { ad, setting, score };
      }
    }
    // Also try matching against the detection name itself
    const detWords = new Set(ad.detection.name.toLowerCase().split(/\W+/).filter(w => w.length > 3));
    const score = needleWords.filter(w => detWords.has(w)).length;
    if (score > 0 && (!best || score > best.score)) {
      const fallbackSetting: Setting = ad.enabledSettings[0] ?? {
        id: ad.detection.id,
        name: ad.detection.name,
        enabled: true,
        description: '',
      };
      best = { ad, setting: fallbackSetting, score };
    }
  }

  return best ? { ad: best.ad, setting: best.setting } : null;
}

// Hard-block categories that produce a violation even when no configured detection matches.
const HARD_BLOCK_KEYWORDS = ['cbrn', 'child', 'csam', 'critical'];

function isHardBlock(category: string): boolean {
  const lower = category.toLowerCase();
  return HARD_BLOCK_KEYWORDS.some(kw => lower.includes(kw));
}

const HARD_BLOCK_MITRE = {
  techniqueId: 'AML.T0054',
  techniqueName: 'LLM Jailbreak',
  tactic: 'ml-attack-staging',
} as const;

// ── Main export ────────────────────────────────────────────────────────────────

export async function checkLayer3Llm(
  prompt: string,
  activeDetections: ActiveDetection[],
  env: Env,
): Promise<Violation[]> {
  console.log('[layer3] ── USER PROMPT ────────────────────────────────────────');
  console.log(prompt.slice(0, 200));
  console.log('[layer3] ────────────────────────────────────────────────────────');

  const result = await env.AI.run('@cf/meta/llama-3.3-70b-instruct-fp8-fast', {
    messages: [
      { role: 'system', content: SYSTEM_PROMPT },
      { role: 'user', content: prompt },
    ],
    max_tokens: 512,
  }) as Record<string, unknown>;

  console.log('[layer3] result type:', typeof result, 'keys:', Object.keys(result ?? {}));

  let jsonToParse: unknown;
  if (result?.response !== null && typeof result?.response === 'object') {
    jsonToParse = result.response;
  } else {
    const raw = (
      typeof result === 'string' ? result as unknown as string :
      typeof result?.response === 'string' ? result.response as string :
      typeof result?.text === 'string' ? result.text as string :
      JSON.stringify(result)
    ).trim();
    console.log('[layer3] raw response:', raw.slice(0, 300));
    const jsonStr = raw.replace(/^```(?:json)?\s*/i, '').replace(/\s*```\s*$/, '').trim();
    jsonToParse = JSON.parse(jsonStr);
  }
  console.log('[layer3] jsonToParse:', JSON.stringify(jsonToParse).slice(0, 300));

  let parsed;
  try {
    parsed = L3ModelOutputSchema.parse(jsonToParse);
  } catch (err) {
    console.error('[layer3] parse error:', err);
    return [];
  }

  // Severity-based confidence floors:
  // High-severity classifications (CBRN, CSAM, explicit violence) need strong
  // confidence before auto-blocking. Medium/low harms are nuanced — a lower
  // floor catches real harm while keeping false-positive risk acceptable.
  const MIN_CONFIDENCE: Record<string, number> = {
    high:   0.90,
    medium: 0.70,
    low:    0.55,
  };
  const violations: Violation[] = [];

  for (const cls of parsed.classifications) {
    const floor = MIN_CONFIDENCE[cls.severity] ?? MIN_CONFIDENCE.medium;
    if (cls.confidence < floor) {
      console.log(`[layer3] discarding low-confidence classification: ${cls.category} severity=${cls.severity} conf=${cls.confidence} floor=${floor}`);
      continue;
    }

    const match = matchToDetection(cls, activeDetections);

    const hardBlock = isHardBlock(cls.category);
    const firstAd = activeDetections[0];

    if (match) {
      violations.push({
        policyName: match.ad.policyName,
        categoryName: match.ad.categoryName,
        detectionName: match.ad.detection.name,
        setting: match.setting.name,
        mode: hardBlock ? 'block' : match.ad.detection.mode,
        confidence: cls.confidence,
        detectedBy: 'llm',
        evidence: cls.evidence,
        mitreAtlas: match.ad.detection.mitreAtlas ?? HARD_BLOCK_MITRE,
      });
    } else {
      // No configured detection matched — but don't discard. The model flagged this
      // with sufficient confidence; emit it as a global safety catch so nothing slips
      // through due to policy gaps. Hard blocks are always 'block'; everything else
      // falls to 'monitor' so the user sees it without auto-blocking.
      violations.push({
        policyName: firstAd?.policyName ?? 'Global Safety Policy',
        categoryName: cls.category,
        detectionName: cls.category,
        setting: cls.subcategory || cls.category,
        mode: hardBlock ? 'block' : 'monitor',
        confidence: cls.confidence,
        detectedBy: 'llm',
        evidence: cls.evidence,
        mitreAtlas: HARD_BLOCK_MITRE,
      });
    }
  }

  return violations;
}
