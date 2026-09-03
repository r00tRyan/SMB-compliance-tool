import type { AiReportInput } from './types.js';

export interface ValidationResult {
  ok: boolean;
  reason?: string;
}

const SECRET_PATTERNS: RegExp[] = [
  /sk-[a-zA-Z0-9]{16,}/, // API-key-ish
  /AKIA[0-9A-Z]{16}/, // AWS access key id
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\bxox[baprs]-[0-9A-Za-z-]{10,}/, // Slack token
];

const COMPLIANCE_CLAIMS: RegExp[] = [
  /\byou (are|'re) (now )?(fully )?compliant\b/i,
  /\bis (now )?(fully )?compliant\b/i,
  /\bcertified\b/i,
  /\baudit[- ]ready\b/i,
  /\bpasses? (the )?(HIPAA|PCI|SOC ?2|ISO ?27001)\b/i,
];

/**
 * Gate AI output before it is shown. On any failure the caller substitutes the
 * deterministic fallback and marks the result degraded.
 */
export function validateAiText(text: string, input: AiReportInput): ValidationResult {
  const trimmed = text.trim();
  if (trimmed.length < 20) return { ok: false, reason: 'output too short' };
  if (trimmed.length > 8_000) return { ok: false, reason: 'output too long' };

  for (const re of SECRET_PATTERNS) {
    if (re.test(trimmed)) return { ok: false, reason: 'output contains a secret-like string' };
  }
  for (const re of COMPLIANCE_CLAIMS) {
    if (re.test(trimmed)) return { ok: false, reason: 'output makes a compliance/certification claim' };
  }

  // No fabricated check ids: any TOKEN that looks like a check id must be one we supplied.
  const allowed = new Set(input.findings.map((f) => f.checkId));
  const mentioned = trimmed.match(/\b[A-Z]{3}-[A-Z0-9]{2,6}-\d{3}\b/g) ?? [];
  for (const id of mentioned) {
    if (!allowed.has(id)) return { ok: false, reason: `output references unknown check id ${id}` };
  }

  // No fabricated finding ids either.
  const allowedFindingIds = new Set(input.findings.map((f) => f.id));
  const findingIdish = trimmed.match(/\bfinding[ _-]?id[:=]?\s*([A-Za-z0-9_-]{6,})/gi) ?? [];
  for (const m of findingIdish) {
    const id = m.split(/[:=\s]+/).pop() ?? '';
    if (id && !allowedFindingIds.has(id)) {
      return { ok: false, reason: 'output references an unknown finding id' };
    }
  }

  return { ok: true };
}
