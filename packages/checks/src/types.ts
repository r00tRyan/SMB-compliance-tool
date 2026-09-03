import type {
  Category,
  CheckReference,
  CheckStatus,
  FrameworkMapping,
  Platform,
  RemediationGuidance,
  Severity,
} from '@smb/shared';

/** Raw text captured by one read-only collector command. */
export interface CollectorOutput {
  /** true if the command ran; false if unavailable / errored / not applicable. */
  ok: boolean;
  /** stdout (or file contents), trimmed. Empty when `ok` is false. */
  text: string;
  /** short reason when `ok` is false (e.g. "command not found"). */
  error?: string;
}

export interface CheckContext {
  asset: { hostname: string; platform: Platform; osVersion: string };
  /** Collector outputs keyed by the ids the check declared in `collectors`. */
  collected: Record<string, CollectorOutput>;
}

/** The scanner's per-check result: Detection only. No severity here. */
export interface CheckOutcome {
  status: CheckStatus;
  /** Minimal, human-readable proof. Rendered as text; never HTML. */
  evidence: string;
}

export type EvaluateFn = (ctx: CheckContext) => CheckOutcome;

/**
 * A single security check. This object is the ONLY source of truth for a
 * check's severity, category, rationale, remediation, and framework mappings.
 * The scanner runs `evaluate`; the server reads the metadata.
 */
export interface SecurityCheck {
  /** Stable id, e.g. "WIN-FW-001". Matches /^[A-Z]{3}-[A-Z0-9]{2,6}-\d{3}$/. */
  id: string;
  name: string;
  description: string;
  platform: Platform;
  category: Category;
  /** Authoritative severity. The server ignores any client-supplied value. */
  severity: Severity;
  /** Why this matters, one or two sentences, security-focused. */
  rationale: string;
  /** Ids of the read-only collectors this check consumes. */
  collectors: string[];
  /** Pure function: (collected evidence) -> status + normalized evidence. */
  evaluate: EvaluateFn;
  remediation: RemediationGuidance;
  frameworks: FrameworkMapping[];
  references: CheckReference[];
  /** Always false in the MVP (read-only detection + human-guided fixes). */
  autoRemediationSupported: false;
}

/** Metadata-only view used by the server (no `evaluate`). */
export type SecurityCheckMeta = Omit<SecurityCheck, 'evaluate'>;
