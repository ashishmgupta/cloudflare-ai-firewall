import type { InspectRequest, InspectResponse, Policy, Violation, Verdict } from '@firewall/shared';
import type { Env } from './env.js';
import { runLayer0 } from './layers/layer0-heuristics.js';
import { hashPrompt, checkLayer1Cache, writeLayer1Cache } from './layers/layer1-cache.js';
import { checkLayer2Vector } from './layers/layer2-vector.js';
import { checkLayer3Llm } from './layers/layer3-llm.js';

function scoreToVerdict(score: number, thresholds: { flag: number; block: number }): Verdict {
  if (score >= thresholds.block) return 'block';
  if (score >= thresholds.flag) return 'flag';
  return 'pass';
}

function buildResponse(
  requestId: string,
  verdict: Verdict,
  score: number,
  policy: Policy,
  violations: Violation[],
  perLayer: Record<string, number>,
  startTime: number,
  cached: boolean,
): InspectResponse {
  return {
    requestId,
    verdict,
    score: Math.round(score),
    policy: { id: policy.id, name: policy.name },
    violations,
    latencyMs: { total: Date.now() - startTime, perLayer },
    cached,
  };
}

export async function runPipeline(
  req: InspectRequest,
  policy: Policy,
  env: Env,
  ctx: ExecutionContext,
  requestId: string,
): Promise<InspectResponse> {
  const startTime = Date.now();
  const perLayer: Record<string, number> = {};

  // ── Layer 0: in-memory heuristics (synchronous, no I/O) ──────────────────
  const l0t = Date.now();
  const layer0 = runLayer0(req.prompt, policy);
  perLayer['layer0'] = Date.now() - l0t;

  // Confident high score → block immediately without touching AI
  if (layer0.confident && layer0.score >= policy.scoreThresholds.block) {
    return buildResponse(requestId, 'block', layer0.score, policy, layer0.violations, perLayer, startTime, false);
  }

  // ── Layers 1 + 2: fire in parallel ───────────────────────────────────────
  const normalizedHash = await hashPrompt(req.prompt);
  const cacheKey = `${normalizedHash}:${policy.id}`;

  const cachePromise = policy.layers.layer1.enabled
    ? checkLayer1Cache(cacheKey, env)
    : Promise.resolve(null);

  const vectorPromise = policy.layers.layer2.enabled
    ? checkLayer2Vector(req.prompt, policy, env)
    : Promise.resolve(null);

  // Cache check takes priority — await it first, abandon vector if hit
  const l1t = Date.now();
  const cacheHit = await cachePromise;
  perLayer['layer1'] = Date.now() - l1t;

  if (cacheHit) {
    return { ...cacheHit, requestId, cached: true };
  }

  const violations: Violation[] = [...layer0.violations];
  let score = layer0.score;

  const l2t = Date.now();
  let vectorViolation: Awaited<ReturnType<typeof checkLayer2Vector>> = null;
  try {
    vectorViolation = await vectorPromise;
    perLayer['layer2'] = Date.now() - l2t;
  } catch {
    perLayer['layer2'] = Date.now() - l2t;
    if (!policy.failOpen) {
      return buildResponse(requestId, 'block', 100, policy, violations, perLayer, startTime, false);
    }
  }

  if (vectorViolation) {
    violations.push(vectorViolation);
    // Weight vector match by similarity score
    const vecScore = vectorViolation.confidence * 100;
    const categoryAction = policy.categoryActions[vectorViolation.category];
    if (categoryAction === 'block') {
      score = Math.max(score, policy.scoreThresholds.block);
    } else {
      score = Math.max(score, vecScore);
    }
  }

  // Short-circuit: already confident after vector
  if (score >= policy.scoreThresholds.block) {
    const response = buildResponse(requestId, 'block', score, policy, violations, perLayer, startTime, false);
    ctx.waitUntil(writeLayer1Cache(cacheKey, response, policy.layers.layer1.ttlSeconds, env));
    return response;
  }

  // ── Layer 3: LLM classification (only for ambiguous prompts) ─────────────
  if (policy.layers.layer3.enabled) {
    const l3t = Date.now();
    try {
      const llmResult = await checkLayer3Llm(req.prompt, req.context ?? [], policy, env);
      perLayer['layer3'] = Date.now() - l3t;

      if (!llmResult.safe) {
        violations.push(...llmResult.violations);

        // Apply per-category actions from policy
        for (const v of llmResult.violations) {
          const action = policy.categoryActions[v.category];
          if (action === 'block') {
            score = Math.max(score, policy.scoreThresholds.block);
          } else if (action === 'flag') {
            score = Math.max(score, policy.scoreThresholds.flag);
          } else {
            score = Math.max(score, 70);
          }
        }
      }
    } catch {
      perLayer['layer3'] = Date.now() - l3t;
      if (!policy.failOpen) {
        return buildResponse(requestId, 'block', 100, policy, violations, perLayer, startTime, false);
      }
      // fail-open: continue with current score + add warning violation
      violations.push({
        category: 'layer3_error',
        categoryName: 'LLM Layer Error (fail-open)',
        layer: 'llm',
        confidence: 0,
        mitreAtlas: { techniqueId: 'N/A', techniqueName: 'N/A', tactic: 'N/A' },
      });
    }
  }

  const verdict = scoreToVerdict(score, policy.scoreThresholds);
  const response = buildResponse(requestId, verdict, score, policy, violations, perLayer, startTime, false);

  // Cache verdict and emit analytics in the background
  ctx.waitUntil(
    Promise.all([
      writeLayer1Cache(cacheKey, response, policy.layers.layer1.ttlSeconds, env),
      emitAnalytics(response, policy, env),
    ]),
  );

  return response;
}

async function emitAnalytics(
  response: InspectResponse,
  policy: Policy,
  env: Env,
): Promise<void> {
  try {
    env.ANALYTICS.writeDataPoint({
      blobs: [response.requestId, policy.id, response.verdict],
      doubles: [response.score, response.latencyMs.total],
      indexes: [policy.tenantId],
    });
  } catch {
    // Analytics failures must never affect the inspection path
  }
}
