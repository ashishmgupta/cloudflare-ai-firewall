export const ATLAS_TECHNIQUES: Record<string, { techniqueId: string; techniqueName: string; tactic: string }> = {
  'AML.T0051': {
    techniqueId: 'AML.T0051',
    techniqueName: 'LLM Prompt Injection',
    tactic: 'ML Attack Staging',
  },
  'AML.T0054': {
    techniqueId: 'AML.T0054',
    techniqueName: 'LLM Jailbreak',
    tactic: 'ML Attack Staging',
  },
  'AML.T0043': {
    techniqueId: 'AML.T0043',
    techniqueName: 'Craft Adversarial Data',
    tactic: 'ML Attack Staging',
  },
  'AML.T0040': {
    techniqueId: 'AML.T0040',
    techniqueName: 'ML Model Inference API Access',
    tactic: 'Initial Access',
  },
  'AML.T0048': {
    techniqueId: 'AML.T0048',
    techniqueName: 'Societal Harm',
    tactic: 'Impact',
  },
};

// Heuristic rule category → ATLAS technique ID
export const DEFAULT_HEURISTIC_ATLAS: Record<string, string> = {
  injection: 'AML.T0051',
  jailbreak: 'AML.T0054',
  delimiter_stacking: 'AML.T0051',
  base64_blob: 'AML.T0043',
  hex_blob: 'AML.T0043',
  unicode_obfuscation: 'AML.T0043',
};

// Llama Guard S-category → ATLAS technique ID
export const DEFAULT_LLM_ATLAS: Record<string, string> = {
  S1: 'AML.T0048',
  S2: 'AML.T0048',
  S3: 'AML.T0048',
  S4: 'AML.T0048',
  S5: 'AML.T0048',
  S6: 'AML.T0048',
  S7: 'AML.T0048',
  S8: 'AML.T0048',
  S9: 'AML.T0048',
  S10: 'AML.T0048',
  S11: 'AML.T0048',
  S12: 'AML.T0048',
  S13: 'AML.T0048',
  S14: 'AML.T0043',
  S15: 'AML.T0051',
  S16: 'AML.T0054',
};

export const LLM_CATEGORY_NAMES: Record<string, string> = {
  S1: 'Violent Crimes',
  S2: 'Non-Violent Crimes',
  S3: 'Sex-Related Crimes',
  S4: 'Child Sexual Exploitation',
  S5: 'Defamation',
  S6: 'Specialized Advice',
  S7: 'Privacy',
  S8: 'Intellectual Property',
  S9: 'Indiscriminate Weapons',
  S10: 'Hate',
  S11: 'Suicide & Self-Harm',
  S12: 'Sexual Content',
  S13: 'Elections',
  S14: 'Code Interpreter Abuse',
  S15: 'Prompt Injection',
  S16: 'Jailbreak Attempt',
};
