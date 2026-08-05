// Granting a workspace a model credential without reaching that provider's API is a
// guaranteed failure, so the endpoints of explicitly granted providers are derived and
// allowed automatically. Derivation happens at create time (when credentials are
// materialized) and never mutates the shared policy, so the policy fingerprint that
// identifies the workspace stays stable.

const PROVIDER_DOMAINS = Object.freeze({
  anthropic: ['api.anthropic.com'],
  openai: ['api.openai.com'],
  azure: ['*.openai.azure.com'],
  google: ['generativelanguage.googleapis.com'],
  'google-vertex': ['aiplatform.googleapis.com', '*.googleapis.com'],
  'github-copilot': ['api.githubcopilot.com', 'api.github.com'],
  opencode: ['opencode.ai', 'api.opencode.ai'],
  'opencode-go': ['opencode.ai', 'api.opencode.ai'],
  openrouter: ['openrouter.ai'],
  deepseek: ['api.deepseek.com'],
  groq: ['api.groq.com'],
  mistral: ['api.mistral.ai'],
  xai: ['api.x.ai'],
  together: ['api.together.xyz'],
  fireworks: ['api.fireworks.ai'],
  cerebras: ['api.cerebras.ai'],
  perplexity: ['api.perplexity.ai'],
  cohere: ['api.cohere.com'],
  huggingface: ['api-inference.huggingface.co', 'huggingface.co'],
  ollama: [],
});

/**
 * Domains required by the providers present in an OPENCODE_AUTH_CONTENT payload.
 * The payload is parsed in memory only; no value from it is ever returned or logged.
 */
export function grantedProviderDomains(authContent) {
  if (typeof authContent !== 'string' || !authContent.trim()) return [];
  let parsed;
  try {
    parsed = JSON.parse(authContent);
  } catch {
    return [];
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return [];
  const domains = new Set();
  for (const provider of Object.keys(parsed)) {
    for (const domain of PROVIDER_DOMAINS[provider] ?? []) domains.add(domain);
  }
  return [...domains];
}

/**
 * Per-workspace egress policy with granted-provider domains merged in. Returns the
 * shared policy untouched for external-proxy mode and when nothing is derived.
 */
export function grantedEgressPolicy(policy, grantedCredentials = {}) {
  if (policy.egress.mode !== 'managed') return policy.egress;
  const derived = grantedProviderDomains(grantedCredentials.OPENCODE_AUTH_CONTENT);
  if (derived.length === 0) return policy.egress;
  const existing = new Set(policy.egress.gatewayPolicy.allowedDomains);
  const added = derived.filter((domain) => !existing.has(domain));
  if (added.length === 0) return policy.egress;
  return {
    ...policy.egress,
    gatewayPolicy: {
      ...policy.egress.gatewayPolicy,
      allowedDomains: [...policy.egress.gatewayPolicy.allowedDomains, ...added],
    },
  };
}

export const KNOWN_PROVIDER_DOMAINS = PROVIDER_DOMAINS;
