/**
 * Cross-cutting domain types. These are the vocabulary the whole platform
 * shares. Enum-like values are declared as `const` arrays so they can be reused
 * for Zod schemas, Prisma enums, and exhaustiveness checks.
 */

export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const PLATFORMS = ['windows', 'linux'] as const;
export type Platform = (typeof PLATFORMS)[number];

/** Result of a single check as reported by the scanner (Detection). */
export const CHECK_STATUSES = ['PASS', 'FAIL', 'WARN', 'ERROR', 'NOT_APPLICABLE'] as const;
export type CheckStatus = (typeof CHECK_STATUSES)[number];

export const CATEGORIES = [
  'Identity & Access',
  'Endpoint Security',
  'Network Security',
  'Patch Management',
  'Data Protection',
  'Logging & Monitoring',
] as const;
export type Category = (typeof CATEGORIES)[number];

/** Lifecycle state of a finding once it exists in the platform. */
export const FINDING_STATUSES = [
  'OPEN',
  'ACKNOWLEDGED',
  'IN_PROGRESS',
  'RESOLVED',
  'ACCEPTED_RISK',
  'FALSE_POSITIVE',
] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];

/** Statuses that mean "this no longer counts against the score". */
export const INACTIVE_FINDING_STATUSES: readonly FindingStatus[] = [
  'RESOLVED',
  'ACCEPTED_RISK',
  'FALSE_POSITIVE',
];

export const REMEDIATION_OWNERS = [
  'Business owner',
  'Employee',
  'IT administrator',
  'Managed service provider',
] as const;
export type RemediationOwner = (typeof REMEDIATION_OWNERS)[number];

export const EFFORT_ESTIMATES = [
  '5 minutes',
  '15 minutes',
  '30 minutes',
  '1 hour',
  'Requires IT support',
] as const;
export type EffortEstimate = (typeof EFFORT_ESTIMATES)[number];

/** Rough minute-cost used by the prioritization engine (lower = easier). */
export const EFFORT_MINUTES: Record<EffortEstimate, number> = {
  '5 minutes': 5,
  '15 minutes': 15,
  '30 minutes': 30,
  '1 hour': 60,
  'Requires IT support': 240,
};

export interface FrameworkMapping {
  /** e.g. "CIS Controls v8" | "NIST CSF 2.0" */
  framework: string;
  /** e.g. "4.1" | "PR.PS-01" */
  controlId: string;
  /** Short human label for the control. Minimal metadata only. */
  controlName: string;
}

export interface RemediationGuidance {
  /** Plain-English description of what was found. */
  whatWeFound: string;
  /** Why it matters, in business terms. */
  whyItMatters: string;
  /** Ordered, concrete steps. */
  recommendedFix: string[];
  who: RemediationOwner;
  effort: EffortEstimate;
  /** How the platform will confirm the fix on re-scan. */
  verification: string;
  /** Extra caution shown prominently when steps carry risk. */
  warning?: string;
}

export interface CheckReference {
  label: string;
  url: string;
}
