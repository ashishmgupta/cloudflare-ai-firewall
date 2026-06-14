import type {
  InspectRequest,
  InspectResponse,
  SecurityProfile,
  Violation,
  Verdict,
  Setting,
  Detection,
} from '@firewall/shared';
import type { Env } from './env.js';
import { type ActiveDetection, runLayer0 } from './layers/layer0-heuristics.js';
import { hashPrompt, checkLayer1Cache, writeLayer1Cache } from './layers/layer1-cache.js';
import { checkLayer2Vector } from './layers/layer2-vector.js';
import { checkLayer3Llm } from './layers/layer3-llm.js';

// Flatten all enabled detections across the profile into one list
export function getActiveDetections(profile: SecurityProfile): ActiveDetection[] {
  const result: ActiveDetection[] = [];
  for (const policy of profile.policies) {
    for (const category of policy.categories) {
      for (const detection of category.detections) {
        const enabledSettings: Setting[] = detection.settings.filter(s => s.enabled);
        // Include if has enabled settings OR has no sub-settings (detection itself is the unit)
        if (enabledSettings.length > 0 || detection.settings.length === 0) {
          result.push({ policyName: policy.name, categoryName: category.name, detection, enabledSettings });
        }
      }
    }
  }
  return result;
}

export function aggregateVerdict(violations: Violation[]): Verdict {
  if (violations.some(v => v.mode === 'block')) return 'block';
  if (violations.length > 0) return 'monitor';
  return 'pass';
}

function buildResponse(
  requestId: string,
  verdict: Verdict,
  profile: SecurityProfile,
  violations: Violation[],
  perLayer: Record<string, number>,
  startTime: number,
  cached: boolean,
): InspectResponse {
  return {
    requestId,
    verdict,
    profile: { id: profile.id, name: profile.name },
    violations,
    latencyMs: { total: Date.now() - startTime, perLayer },
    cached,
  };
}

export async function runPipeline(
  req: InspectRequest,
  profile: SecurityProfile,
  env: Env,
  ctx: ExecutionContext,
  requestId: string,
  bypassCache = false,
): Promise<InspectResponse> {
  const startTime = Date.now();
  const perLayer: Record<string, number> = {};

  const activeDetections = getActiveDetections(profile);
  if (activeDetections.length === 0) {
    return buildResponse(requestId, 'pass', profile, [], perLayer, startTime, false);
  }

  // ── Layer 0: synchronous heuristics (0ms I/O) ─────────────────────────────
  const l0t = Date.now();
  const l0Violations = runLayer0(req.prompt, activeDetections);
  perLayer['layer0'] = Date.now() - l0t;

  // Immediate block on confident heuristic (no need to call AI)
  if (l0Violations.some(v => v.mode === 'block')) {
    return buildResponse(requestId, 'block', profile, l0Violations, perLayer, startTime, false);
  }

  // ── Layer 1 (cache) + Layer 2 (vector): parallel I/O ─────────────────────
  const normalizedHash = await hashPrompt(req.prompt);
  const cacheKey = `${normalizedHash}:${profile.id}`;

  const cachePromise = !bypassCache
    ? checkLayer1Cache(cacheKey, env)
    : Promise.resolve(null);

  const needsVector = !!env.FIREWALL_VECTORIZE && activeDetections.some(
    ad => ad.detection.id === 'det-injection' || ad.detection.id === 'det-jailbreak',
  );
  const vectorPromise = needsVector
    ? checkLayer2Vector(req.prompt, activeDetections, env)
    : Promise.resolve([] as Violation[]);

  const l1t = Date.now();
  const cacheHit = await cachePromise;
  perLayer['layer1'] = Date.now() - l1t;

  if (cacheHit) {
    return { ...cacheHit, requestId, cached: true };
  }

  const violations: Violation[] = [...l0Violations];

  const l2t = Date.now();
  try {
    const l2Violations = await vectorPromise;
    perLayer['layer2'] = Date.now() - l2t;
    violations.push(...l2Violations);
  } catch {
    perLayer['layer2'] = Date.now() - l2t;
    if (!profile.failOpen) {
      return buildResponse(requestId, 'block', profile, violations, perLayer, startTime, false);
    }
  }

  // Short-circuit: block from combined L0+L2
  if (violations.some(v => v.mode === 'block')) {
    const response = buildResponse(requestId, 'block', profile, violations, perLayer, startTime, false);
    ctx.waitUntil(writeLayer1Cache(cacheKey, response, profile.cacheTtlSeconds, env));
    return response;
  }

  // ── Layer 3: LLM for Content Moderation detections ────────────────────────
  const l3Detections = activeDetections.filter(
    ad => ad.detection.id === 'det-content-mod' || ad.categoryName === 'Content Moderation',
  );

  // Skip L3 on very short prompts — LLM has insufficient context and false-positive
  // rate is unacceptably high below 8 words (industry standard minimum).
  const wordCount = req.prompt.trim().split(/\s+/).filter(Boolean).length;

  if (l3Detections.length > 0 && wordCount >= 8) {
    const l3t = Date.now();
    try {
      const l3Violations = await checkLayer3Llm(req.prompt, l3Detections, env);
      perLayer['layer3'] = Date.now() - l3t;
      violations.push(...l3Violations);
    } catch (err) {
      perLayer['layer3'] = Date.now() - l3t;
      console.error('[pipeline] layer3 error:', err);
      if (!profile.failOpen) {
        return buildResponse(requestId, 'block', profile, violations, perLayer, startTime, false);
      }
    }
  }

  const verdict = aggregateVerdict(violations);
  const response = buildResponse(requestId, verdict, profile, violations, perLayer, startTime, false);

  ctx.waitUntil(writeLayer1Cache(cacheKey, response, profile.cacheTtlSeconds, env));

  return response;
}
