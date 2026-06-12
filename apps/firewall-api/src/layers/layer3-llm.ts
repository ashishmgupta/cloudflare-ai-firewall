import type { Policy, Violation } from '@firewall/shared';
import {
  ATLAS_TECHNIQUES,
  DEFAULT_LLM_ATLAS,
  LLM_CATEGORY_NAMES,
} from '@firewall/shared';
import type { Env } from '../env.js';

export interface Layer3Result {
  safe: boolean;
  violations: Violation[];
  rawResponse: string;
}

function buildGuardPrompt(prompt: string, context: string[]): string {
  const conversation = context.length > 0
    ? context.map((c, i) => `${i % 2 === 0 ? 'Assistant' : 'User'}: ${c}`).join('\n') + `\nUser: ${prompt}`
    : `User: ${prompt}`;

  return `[INST] Task: Check if there is unsafe content in the 'User' message in the following conversation according to our safety policy.

<BEGIN UNSAFE CONTENT CATEGORIES>
S1: Violent Crimes - Content that enables or glorifies violence.
S2: Non-Violent Crimes - Content that enables fraud, theft, cybercrime.
S3: Sex-Related Crimes - Sexual assault facilitation.
S4: Child Sexual Exploitation - Any CSAM or grooming content.
S5: Defamation - False statements of fact about real persons.
S6: Specialized Advice - Medical/legal/financial advice without disclaimers.
S7: Privacy - Personal data exposure or doxxing.
S8: Intellectual Property - Verbatim reproduction of copyrighted content.
S9: Indiscriminate Weapons - Instructions for WMDs.
S10: Hate - Content that promotes hatred based on protected characteristics.
S11: Suicide & Self-Harm - Content that facilitates self-harm.
S12: Sexual Content - Explicit sexual content.
S13: Elections - False information about voting/candidates.
S14: Code Interpreter Abuse - Malicious code execution or data exfiltration.
<END UNSAFE CONTENT CATEGORIES>

<BEGIN CONVERSATION>
${conversation}
<END CONVERSATION>

Provide your safety assessment for the User message only:
- First line must read 'safe' or 'unsafe'.
- If unsafe, second line must include a comma-separated list of violated categories. [/INST]`;
}

export async function checkLayer3Llm(
  prompt: string,
  context: string[],
  policy: Policy,
  env: Env,
): Promise<Layer3Result> {
  const guardPrompt = buildGuardPrompt(prompt, context);

  const result = await env.AI.run('@cf/meta/llama-guard-3-8b', {
    messages: [{ role: 'user', content: guardPrompt }],
  }) as { response: string };

  const raw = (result.response ?? '').trim();
  const lines = raw.split('\n').map(l => l.trim()).filter(Boolean);
  const firstLine = lines[0]?.toLowerCase() ?? '';

  if (firstLine !== 'unsafe') {
    return { safe: true, violations: [], rawResponse: raw };
  }

  const categories = (lines[1] ?? '')
    .split(',')
    .map(c => c.trim().toUpperCase())
    .filter(c => /^S\d+$/.test(c));

  const violations: Violation[] = categories.map(cat => {
    const action = policy.categoryActions[cat];
    const atlasId = policy.mitreAtlasMappings[cat]?.techniqueId ??
      DEFAULT_LLM_ATLAS[cat] ?? 'AML.T0048';
    const technique = ATLAS_TECHNIQUES[atlasId] ?? ATLAS_TECHNIQUES['AML.T0048']!;

    return {
      category: cat,
      categoryName: LLM_CATEGORY_NAMES[cat] ?? cat,
      layer: 'llm' as const,
      confidence: action === 'block' ? 0.95 : 0.8,
      mitreAtlas: technique,
    };
  });

  return { safe: false, violations, rawResponse: raw };
}
