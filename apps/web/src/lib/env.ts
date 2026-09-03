import { z } from 'zod';

const schema = z.object({
  DATABASE_URL: z.string().url(),
  AUTH_SECRET: z.string().min(16, 'AUTH_SECRET must be at least 16 characters'),
  APP_URL: z.string().url().default('http://localhost:3000'),
  ANTHROPIC_API_KEY: z.string().optional().default(''),
  ANTHROPIC_MODEL: z.string().default('claude-sonnet-5'),
  ANTHROPIC_MAX_TOKENS: z.coerce.number().int().positive().default(1500),
  SCAN_MAX_BYTES: z.coerce.number().int().positive().default(1_048_576),
  ENABLE_DEMO_SEED: z
    .string()
    .optional()
    .transform((v) => v === 'true'),
  DEMO_EMAIL: z.string().optional().default('owner@acmedental.example'),
  DEMO_PASSWORD: z.string().optional().default('demo-password-local-only'),
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
});

/** Parsed once at module load. Throws early with a clear message on misconfig. */
export const env = (() => {
  const parsed = schema.safeParse(process.env);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `  ${i.path.join('.')}: ${i.message}`).join('\n');
    throw new Error(`Invalid environment configuration:\n${issues}`);
  }
  return parsed.data;
})();

export const isProd = env.NODE_ENV === 'production';
export const aiConfigured = env.ANTHROPIC_API_KEY.length > 0;
/**
 * Mark session cookies `Secure` only when the app is actually served over HTTPS.
 * Driven by APP_URL, not NODE_ENV — the local `docker compose up` stack runs a
 * production build over plain http://localhost, where a Secure cookie would be
 * silently dropped and log-in would appear to fail.
 */
export const cookieSecure = env.APP_URL.startsWith('https://');
