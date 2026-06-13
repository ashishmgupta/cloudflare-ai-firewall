import type { Detection, Setting, Violation } from '@firewall/shared';

export interface ActiveDetection {
  policyName: string;
  categoryName: string;
  detection: Detection;
  enabledSettings: Setting[];
}

// ─── Context-aware PII helpers ────────────────────────────────────────────────

function contextAwareMatch(
  prompt: string,
  valuePattern: RegExp,
  contextPattern: RegExp,
  windowChars: number,
): string | null {
  const match = valuePattern.exec(prompt);
  if (!match) return null;
  const start = Math.max(0, match.index - windowChars);
  const end = Math.min(prompt.length, match.index + match[0].length + windowChars);
  const window = prompt.slice(start, end);
  if (!contextPattern.test(window)) return null; // bare value without context must NOT trigger
  return match[0];
}

function matchFirst(prompt: string, patterns: RegExp[]): string | null {
  for (const p of patterns) {
    const m = p.exec(prompt);
    if (m) return m[0];
  }
  return null;
}

function luhnCheck(numStr: string): boolean {
  const digits = numStr.replace(/\D/g, '');
  let sum = 0, double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = parseInt(digits[i]);
    if (double) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

// ─── Per-setting rule implementations ────────────────────────────────────────
// Returns matched evidence string, or null if no match.

const SETTING_RULES = new Map<string, (prompt: string) => string | null>([
  // PII — context-aware (bare patterns without context must NOT trigger)
  ['set-ssn', (p) => contextAwareMatch(
    p,
    /\b\d{3}-\d{2}-\d{4}\b/,
    /\b(?:ssn|social\s+security|social|identification|id|number|account)\b/i,
    80,
  )],
  ['set-credit-card', (p) => {
    const pattern = /\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})\s*[\d\s\-]{11,18}\d\b/;
    const context = /\b(?:card|credit|debit|visa|mastercard|amex|payment|charge)\b/i;
    const match = contextAwareMatch(p, pattern, context, 80);
    if (!match) return null;
    return luhnCheck(match) ? match : null;
  }],
  ['set-phone', (p) => contextAwareMatch(
    p,
    /\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/,
    /\b(?:phone|mobile|cell|call|text|number|contact|reach)\b/i,
    60,
  )],
  ['set-email', (p) => contextAwareMatch(
    p,
    /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/,
    /\b(?:email|mail|address|contact|send|reach)\b/i,
    60,
  )],

  // Technical Information — no context required (presence is already significant)
  ['set-ip', (p) => {
    const m = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/.exec(p);
    return m ? m[0] : null;
  }],
  ['set-mac', (p) => {
    const m = /\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b/.exec(p);
    return m ? m[0] : null;
  }],
  ['set-api-secret', (p) => {
    const m = /(?:api[_\-]?key|api[_\-]?secret|access[_\-]?token|auth[_\-]?token|bearer[_\-]?token|private[_\-]?key|secret[_\-]?key|password|passwd|pwd)\s*[:=\s]\s*['"]?[A-Za-z0-9_\-\.\/+]{10,}['"]?/i.exec(p);
    return m ? m[0].slice(0, 60) : null;
  }],
  ['set-url', (p) => {
    const m = /https?:\/\/[^\s,>'"]{8,}/.exec(p);
    return m ? m[0] : null;
  }],

  // Security Controls — Prompt Injection (no context required)
  ['set-inj-override', (p) => matchFirst(p, [
    /ignore\s+(?:(?:all|any|the|your|these|prior|previous|further)\s+)*instructions?/i,
    /forget\s+(?:(?:all|any|the|your|these|prior|previous)\s+)*instructions?/i,
    /override\s+(?:your\s+)?(?:instructions?|programming|training|guidelines?)/i,
    /disregard\s+(?:(?:all|any|your|the|previous|prior|these)\s+)*(?:instructions?|rules?|guidelines?)/i,
    /discard\s+(?:your\s+)?(?:current\s+)?(?:instructions?|context|guidelines?|rules?|constraints?)/i,
    /(?:no\s+longer|not\s+(?:to\s+)?follow|stop\s+following)\s+(?:your\s+)?(?:instructions?|guidelines?|rules?)/i,
  ])],
  ['set-inj-token', (p) => matchFirst(p, [
    /new\s+(?:system\s+)?instructions?\s*:/i,
    /<\|system\|>/i,
    /\[system\]/i,
    /###\s*(?:system|instruction|prompt)\b/i,
    /(?:system|assistant)\s+prompt\s*:/i,
  ])],
  ['set-inj-mode-switch', (p) =>
    /switch\s+to\s+(?:unrestricted|unfiltered|uncensored|developer|admin|god)\s+mode/i.exec(p)?.[0] ?? null
  ],

  // Security Controls — Jailbreak
  ['set-jbk-dan', (p) => matchFirst(p, [
    /\bjailbreak\b/i,
    /\bdan\b.*\bdo\s+anything\s+now\b/i,
  ])],
  ['set-jbk-dev-mode', (p) =>
    /developer\s+mode\s*(?:enabled|on|activated)/i.exec(p)?.[0] ?? null
  ],
  ['set-jbk-roleplay', (p) => matchFirst(p, [
    /you\s+are\s+now\s+(?:a|an|the)\s+/i,
    /act\s+as\s+(?:if\s+you\s+(?:are|were)|a\s+)/i,
    /pretend\s+(?:you\s+are|to\s+be)/i,
    /roleplay\s+as\b/i,
  ])],
  ['set-jbk-persistence', (p) =>
    /from\s+now\s+on[,\s]+you\s+(?:will|must|should|are)/i.exec(p)?.[0] ?? null
  ],

  // Obfuscation
  ['set-obf-base64', (p) => {
    const m = /[A-Za-z0-9+/]{60,}={0,2}/.exec(p);
    return m ? `[base64 blob ${m[0].length} chars]` : null;
  }],
  ['set-obf-hex', (p) => {
    const m = /0x[0-9a-fA-F]{40,}/.exec(p);
    return m ? m[0].slice(0, 20) + '…' : null;
  }],
  ['set-obf-unicode', (p) => {
    const zwsp = /[​-‏‪-‮⁠-⁯﻿]/.exec(p);
    return zwsp ? '[zero-width unicode chars]' : null;
  }],
  ['set-obf-delimiter', (p) => {
    const m = /([=\-#*_]{3,}\s*){4,}/.exec(p);
    return m ? m[0].trim().slice(0, 40) : null;
  }],
]);

// ─── Layer 0 entry point ──────────────────────────────────────────────────────

export function runLayer0(prompt: string, activeDetections: ActiveDetection[]): Violation[] {
  const violations: Violation[] = [];

  for (const ad of activeDetections) {
    // Content Moderation has no L0 rules — handled entirely by Layer 3
    if (ad.detection.id === 'det-content-mod') continue;

    for (const setting of ad.enabledSettings) {
      const rule = SETTING_RULES.get(setting.id);
      if (!rule) continue;

      const evidence = rule(prompt);
      if (evidence === null) continue;

      violations.push({
        policyName: ad.policyName,
        categoryName: ad.categoryName,
        detectionName: ad.detection.name,
        setting: setting.name,
        mode: ad.detection.mode,
        confidence: 0.9,
        detectedBy: 'heuristic',
        evidence,
        mitreAtlas: ad.detection.mitreAtlas,
      });
    }
  }

  return violations;
}
