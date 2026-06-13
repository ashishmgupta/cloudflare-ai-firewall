import type { Violation } from '@firewall/shared';
import { ATLAS_TECHNIQUES } from '@firewall/shared';
import type { Env } from '../env.js';
import type { ActiveDetection } from './layer0-heuristics.js';

// Runs for Security Controls detections (injection/jailbreak) only.
// Returns violations whose mitreAtlas is sourced from the matching active detection.
export async function checkLayer2Vector(
  prompt: string,
  activeDetections: ActiveDetection[],
  env: Env,
): Promise<Violation[]> {
  if (!env.FIREWALL_VECTORIZE) return [];

  const embedResult = await env.AI.run('@cf/baai/bge-small-en-v1.5', { text: [prompt] });
  const vector = (embedResult as { data: number[][] }).data[0];
  if (!vector) return [];

  const queryResult = await env.FIREWALL_VECTORIZE.query(vector, { topK: 5, returnMetadata: 'all' });
  const topMatch = queryResult.matches[0];
  if (!topMatch || topMatch.score < 0.82) return [];

  const meta = (topMatch.metadata ?? {}) as Record<string, string>;
  const matchCategory = meta['category'] ?? 'injection';
  const matchAtlasId = meta['mitreAtlasId'] ?? 'AML.T0051';
  const matchDesc = meta['description'] ?? 'Vector similarity match';

  // Find the most relevant active detection for this vector match
  const ad = activeDetections.find(d =>
    d.detection.id === 'det-injection' || d.detection.id === 'det-jailbreak'
  );
  if (!ad) return [];

  const mitreAtlas = ad.detection.mitreAtlas ??
    ATLAS_TECHNIQUES[matchAtlasId] ??
    ATLAS_TECHNIQUES['AML.T0051']!;

  return [{
    policyName: ad.policyName,
    categoryName: ad.categoryName,
    detectionName: ad.detection.name,
    setting: matchDesc.slice(0, 80),
    mode: ad.detection.mode,
    confidence: topMatch.score,
    detectedBy: 'vector',
    evidence: `similarity ${topMatch.score.toFixed(3)} (${matchCategory})`,
    mitreAtlas,
  }];
}
