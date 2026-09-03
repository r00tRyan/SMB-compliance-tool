import { deterministicText } from './fallback.js';
import { buildPrompt } from './prompt.js';
import type { AiArtifact, AiClientConfig, AiReportInput, AiTextResult, GenerateFn } from './types.js';
import { validateAiText } from './validate.js';

const DEFAULT_MODEL = 'claude-sonnet-5';
const DEFAULT_MAX_TOKENS = 1500;
const TIMEOUT_MS = 30_000;

/** Real transport, lazily importing the SDK so the package has no hard runtime cost when AI is off. */
function anthropicTransport(apiKey: string): GenerateFn {
  return async ({ system, messages, model, maxTokens }) => {
    const { default: Anthropic } = await import('@anthropic-ai/sdk');
    const client = new Anthropic({ apiKey, timeout: TIMEOUT_MS, maxRetries: 1 });
    const res = await client.messages.create({
      model,
      max_tokens: maxTokens,
      system,
      messages,
    });
    const text = res.content
      .filter((b): b is Extract<typeof b, { type: 'text' }> => b.type === 'text')
      .map((b) => b.text)
      .join('\n')
      .trim();
    return { text };
  };
}

export interface AiClient {
  readonly enabled: boolean;
  generate(artifact: AiArtifact, input: AiReportInput): Promise<AiTextResult>;
}

/**
 * The client always returns a usable result. If AI is disabled or anything at
 * all goes wrong (no key, network, rate limit, timeout, invalid output), it
 * returns the deterministic fallback with `degraded: true` — never throws.
 */
export function createAiClient(config: AiClientConfig = {}): AiClient {
  const model = config.model ?? DEFAULT_MODEL;
  const maxTokens = config.maxTokens ?? DEFAULT_MAX_TOKENS;
  const transport: GenerateFn | undefined =
    config.generate ?? (config.apiKey ? anthropicTransport(config.apiKey) : undefined);
  const enabled = Boolean(transport);

  return {
    enabled,
    async generate(artifact, input): Promise<AiTextResult> {
      if (!transport) {
        return {
          text: deterministicText(artifact, input),
          degraded: true,
          model: null,
          degradedReason: 'ai_disabled',
        };
      }
      const { system, messages } = buildPrompt(artifact, input);
      try {
        const { text } = await transport({ system, messages, model, maxTokens });
        const check = validateAiText(text, input);
        if (!check.ok) {
          return {
            text: deterministicText(artifact, input),
            degraded: true,
            model,
            degradedReason: `validation_failed:${check.reason ?? 'unknown'}`,
          };
        }
        return { text: text.trim(), degraded: false, model };
      } catch (err) {
        return {
          text: deterministicText(artifact, input),
          degraded: true,
          model,
          degradedReason: `ai_error:${err instanceof Error ? err.name : 'unknown'}`,
        };
      }
    },
  };
}
