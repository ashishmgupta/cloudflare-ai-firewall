import type { Policy, Violation } from '@firewall/shared';
import { ATLAS_TECHNIQUES } from '@firewall/shared';
import type { Env } from '../env.js';

export async function checkLayer2Vector(
  prompt: string,
  policy: Policy,
  env: Env,
): Promise<Violation | null> {
  if (!policy.layers.layer2.enabled || !env.FIREWALL_VECTORIZE) return null;

  const threshold = policy.layers.layer2.similarityThreshold;

  // Embed with small model — fast and runs on Workers AI edge
  const embedResult = await env.AI.run('@cf/baai/bge-small-en-v1.5', {
    text: [prompt],
  });

  const vector = (embedResult as { data: number[][] }).data[0];
  if (!vector) return null;

  const queryResult = await env.FIREWALL_VECTORIZE!.query(vector, {
    topK: 5,
    returnMetadata: 'all',
  });

  const topMatch = queryResult.matches[0];
  if (!topMatch || topMatch.score < threshold) return null;

  const meta = (topMatch.metadata ?? {}) as Record<string, string>;
  const category = meta['category'] ?? 'unknown_attack';
  const atlasId = meta['mitreAtlasId'] ?? 'AML.T0051';
  const technique = policy.mitreAtlasMappings[category] ??
    ATLAS_TECHNIQUES[atlasId] ??
    ATLAS_TECHNIQUES['AML.T0051']!;

  return {
    category,
    categoryName: meta['description'] ?? 'Vector similarity match',
    layer: 'vector',
    confidence: topMatch.score,
    mitreAtlas: technique,
  };
}
