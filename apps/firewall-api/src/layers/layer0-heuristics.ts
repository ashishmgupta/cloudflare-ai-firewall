import type { Policy, Violation } from '@firewall/shared';
import {
  ATLAS_TECHNIQUES,
  DEFAULT_HEURISTIC_ATLAS,
} from '@firewall/shared';

interface HeuristicRule {
  id: string;
  pattern: RegExp;
  weight: number;
  category: string;
  description: string;
}

// Compiled once at module load — never inside a request handler
const INJECTION_RULES: HeuristicRule[] = [
  { id: 'INJ001', pattern: /ignore\s+(?:(?:all|any|the|your|these|prior|previous|further)\s+)*instructions?/i, weight: 75, category: 'injection', description: 'Instruction override attempt' },
  { id: 'INJ002', pattern: /forget\s+(?:(?:all|any|the|your|these|prior|previous)\s+)*instructions?/i, weight: 75, category: 'injection', description: 'Instruction reset attempt' },
  { id: 'INJ003', pattern: /new\s+(system\s+)?instructions?\s*:/i, weight: 45, category: 'injection', description: 'New instructions injection' },
  { id: 'INJ004', pattern: /<\|system\|>/i, weight: 45, category: 'injection', description: 'Llama format system token injection' },
  { id: 'INJ005', pattern: /\[system\]/i, weight: 40, category: 'injection', description: 'System block injection' },
  { id: 'INJ006', pattern: /###\s*(system|instruction|prompt)\b/i, weight: 40, category: 'injection', description: 'Markdown system block injection' },
  { id: 'INJ007', pattern: /override\s+(your\s+)?(instructions?|programming|training|guidelines?)/i, weight: 45, category: 'injection', description: 'Direct override attempt' },
  { id: 'INJ008', pattern: /disregard\s+(?:(?:all|any|your|the|previous|prior|these)\s+)*(instructions?|rules?|guidelines?)/i, weight: 75, category: 'injection', description: 'Disregard instruction attempt' },
  { id: 'INJ009', pattern: /(system|assistant)\s+prompt\s*:/i, weight: 35, category: 'injection', description: 'System prompt reference with colon' },
  { id: 'INJ010', pattern: /discard\s+(?:your\s+)?(?:current\s+)?(?:instructions?|context|guidelines?|rules?|operating\s+context|constraints?)/i, weight: 75, category: 'injection', description: 'Context/instruction discard attempt' },
  { id: 'INJ011', pattern: /switch\s+to\s+(?:unrestricted|unfiltered|uncensored|developer|admin|god)\s+mode/i, weight: 75, category: 'injection', description: 'Restricted mode switch attempt' },
  { id: 'INJ012', pattern: /(?:no\s+longer|not\s+(?:to\s+)?follow|stop\s+following)\s+(?:your\s+)?(?:instructions?|guidelines?|rules?|restrictions?|constraints?)/i, weight: 60, category: 'injection', description: 'Instruction abandonment attempt' },
  { id: 'JBK001', pattern: /\bjailbreak\b/i, weight: 55, category: 'jailbreak', description: 'Explicit jailbreak keyword' },
  { id: 'JBK002', pattern: /\bdan\b.*\bdo\s+anything\s+now\b/i, weight: 60, category: 'jailbreak', description: 'DAN jailbreak pattern' },
  { id: 'JBK003', pattern: /developer\s+mode\s*(enabled|on|activated)/i, weight: 45, category: 'jailbreak', description: 'Developer mode jailbreak' },
  { id: 'JBK004', pattern: /you\s+are\s+now\s+(?:a|an|the)\s+/i, weight: 35, category: 'jailbreak', description: 'Role reassignment' },
  { id: 'JBK005', pattern: /act\s+as\s+(?:if\s+you\s+(?:are|were)|a\s+)/i, weight: 35, category: 'jailbreak', description: 'Act-as jailbreak' },
  { id: 'JBK006', pattern: /pretend\s+(?:you\s+are|to\s+be)/i, weight: 35, category: 'jailbreak', description: 'Pretend roleplay jailbreak' },
  { id: 'JBK007', pattern: /roleplay\s+as\b/i, weight: 35, category: 'jailbreak', description: 'Roleplay override' },
  { id: 'JBK008', pattern: /from\s+now\s+on[,\s]+you\s+(?:will|must|should|are)/i, weight: 40, category: 'jailbreak', description: 'Persistent behavior override' },
];

const STRUCTURAL_RULES: HeuristicRule[] = [
  { id: 'STR001', pattern: /([=\-#*_]{3,}\s*){4,}/g, weight: 10, category: 'delimiter_stacking', description: 'Repeated delimiter stacking' },
  { id: 'STR002', pattern: /[A-Za-z0-9+/]{100,}={0,2}/g, weight: 15, category: 'base64_blob', description: 'Suspected base64 encoded content' },
  { id: 'STR003', pattern: /0x[0-9a-fA-F]{40,}/g, weight: 15, category: 'hex_blob', description: 'Suspected hex encoded content' },
];

const UNICODE_ZWSP = /[​-‏‪-‮⁠-⁯﻿]+/;

export interface Layer0Result {
  score: number;
  violations: Violation[];
  confident: boolean;
}

export function runLayer0(prompt: string, policy: Policy): Layer0Result {
  if (!policy.layers.layer0.enabled) {
    return { score: 0, violations: [], confident: false };
  }

  let score = 0;
  const violations: Violation[] = [];

  // Check byte size
  const byteLen = new TextEncoder().encode(prompt).length;
  if (byteLen > 32 * 1024) {
    score = Math.min(100, score + 20);
  }

  // Unicode zero-width character obfuscation
  if (UNICODE_ZWSP.test(prompt)) {
    score = Math.min(100, score + 20);
    const atlasId = DEFAULT_HEURISTIC_ATLAS['unicode_obfuscation'] ?? 'AML.T0043';
    const technique = ATLAS_TECHNIQUES[atlasId]!;
    violations.push({
      category: 'unicode_obfuscation',
      categoryName: 'Unicode Obfuscation',
      layer: 'heuristic',
      confidence: 0.7,
      mitreAtlas: technique,
    });
  }

  // Apply injection + jailbreak rules
  for (const rule of [...INJECTION_RULES, ...STRUCTURAL_RULES]) {
    if (rule.pattern.test(prompt)) {
      score = Math.min(100, score + rule.weight);
      const atlasId = DEFAULT_HEURISTIC_ATLAS[rule.category] ?? 'AML.T0051';
      const technique = ATLAS_TECHNIQUES[atlasId]!;

      // Merge policy ATLAS overrides if present
      const policyAtlas = policy.mitreAtlasMappings[rule.category];
      violations.push({
        category: rule.category,
        categoryName: rule.description,
        layer: 'heuristic',
        confidence: Math.min(1, rule.weight / 50),
        mitreAtlas: policyAtlas ?? technique,
      });
    }
  }

  // Confident if score crosses block threshold, or clearly clean
  const confident = score >= policy.scoreThresholds.block || score < 15;

  return { score, violations, confident };
}
