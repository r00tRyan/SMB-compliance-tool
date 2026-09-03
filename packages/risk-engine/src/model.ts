/**
 * The deterministic scoring model. Every constant here is documented in
 * packages/risk-engine/SCORING.md. AI is never involved in any number produced
 * by this package.
 */
import type { Category, Severity } from '@smb/shared';

/** Penalty points a single failing check deducts from its asset's 100. */
export const SEVERITY_PENALTY: Record<Severity, number> = {
  CRITICAL: 40,
  HIGH: 20,
  MEDIUM: 8,
  LOW: 3,
  INFO: 0,
};

/** Weight used by the prioritization engine (INFO is >0 so it can still rank). */
export const SEVERITY_PRIORITY_WEIGHT: Record<Severity, number> = {
  CRITICAL: 40,
  HIGH: 20,
  MEDIUM: 8,
  LOW: 3,
  INFO: 1,
};

/** Network-exposed problems are worth fixing sooner. */
export const EXPOSURE_FACTOR: Record<Category, number> = {
  'Network Security': 1.3,
  'Identity & Access': 1.15,
  'Endpoint Security': 1.1,
  'Data Protection': 1.1,
  'Patch Management': 1.0,
  'Logging & Monitoring': 0.9,
};

/** Effort divisor: quick wins get a mild ranking boost. */
export function effortDivisor(effortMinutes: number): number {
  if (effortMinutes <= 5) return 1.0;
  if (effortMinutes <= 15) return 1.1;
  if (effortMinutes <= 30) return 1.3;
  if (effortMinutes <= 60) return 1.6;
  return 2.2;
}

/** A scanner ERROR result is a lower-confidence signal. */
export const LOW_CONFIDENCE_FACTOR = 0.6;

export const SCORE_BANDS = [
  { min: 90, label: 'Excellent' },
  { min: 75, label: 'Good' },
  { min: 60, label: 'Moderate' },
  { min: 40, label: 'Weak' },
  { min: 0, label: 'Critical' },
] as const;

export type ScoreBand = (typeof SCORE_BANDS)[number]['label'];

export function bandFor(score: number): ScoreBand {
  for (const b of SCORE_BANDS) if (score >= b.min) return b.label;
  return 'Critical';
}

export const clamp = (n: number, lo = 0, hi = 100): number => Math.min(hi, Math.max(lo, n));
