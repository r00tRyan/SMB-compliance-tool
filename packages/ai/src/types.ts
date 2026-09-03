import type { Severity } from '@smb/shared';

/** The ONLY shape sent to the model. Deliberately minimal (see docs/AI.md). */
export interface AiFinding {
  id: string;
  checkId: string;
  title: string;
  severity: Severity;
  category: string;
  affectedAssets: number;
  /** deterministic plain-English description from the check definition */
  whatWeFound: string;
  /** deterministic remediation summary from the check definition */
  recommendedFix: string;
  /** framework control ids, e.g. ["CIS 4.5", "NIST PR.IR-01"] */
  frameworks: string[];
}

export interface AiReportInput {
  organization: string;
  isDemo: boolean;
  score: number;
  band: string;
  counts: { critical: number; high: number; medium: number; low: number };
  assetCount: number;
  findings: AiFinding[];
}

export type AiArtifact = 'executive-summary' | 'remediation-plan' | 'finding-explanation' | 'report-narrative';

export interface AiTextResult {
  text: string;
  /** true when the deterministic fallback produced this (no/failed AI). */
  degraded: boolean;
  model: string | null;
  /** why it degraded, for logs (never shown raw to end users). */
  degradedReason?: string;
}

/** Injected transport so the client is unit-testable without network. */
export type GenerateFn = (args: {
  system: string;
  messages: { role: 'user'; content: string }[];
  model: string;
  maxTokens: number;
}) => Promise<{ text: string }>;

export interface AiClientConfig {
  apiKey?: string | undefined;
  model?: string;
  maxTokens?: number;
  /** test/override hook; defaults to the real Anthropic SDK when apiKey is set */
  generate?: GenerateFn;
}
