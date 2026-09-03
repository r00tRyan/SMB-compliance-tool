import type { FindingStatus } from '@prisma/client';

/** Raw scanner statuses that mean "this control is currently a problem". */
export const FAILING_RAW = new Set(['FAIL', 'WARN']);
/** Raw scanner statuses that mean "this control is currently fine". */
export const PASSING_RAW = new Set(['PASS', 'NOT_APPLICABLE']);
// 'ERROR' means "could not assess" — it neither opens nor closes a finding.

export interface TransitionDecision {
  /** the finding status after this observation */
  nextStatus: FindingStatus;
  /** true when the finding row should exist at all after this scan */
  keep: boolean;
  reason: string;
}

/**
 * Pure function: given the existing finding status (or null if none) and the
 * newly observed raw scanner status, decide the lifecycle transition.
 *
 * Rules:
 *  - new problem            -> OPEN
 *  - still failing          -> keep current status (OPEN/ACK/IN_PROGRESS), refresh lastDetected
 *  - was failing, now pass  -> RESOLVED
 *  - user-set terminal states (RESOLVED/ACCEPTED_RISK/FALSE_POSITIVE):
 *      * pass again -> stays RESOLVED / respective terminal state
 *      * fail again -> REOPENS to OPEN (a regression)
 *  - ERROR observation      -> no change
 */
export function decideTransition(
  current: FindingStatus | null,
  observedRaw: string,
): TransitionDecision | null {
  const failing = FAILING_RAW.has(observedRaw);
  const passing = PASSING_RAW.has(observedRaw);

  // Could-not-assess: never creates or changes a finding.
  if (!failing && !passing) {
    if (current == null) return null;
    return { nextStatus: current, keep: true, reason: 'observation_error_no_change' };
  }

  if (current == null) {
    return failing
      ? { nextStatus: 'OPEN', keep: true, reason: 'new_finding' }
      : null; // passing + no prior finding => nothing to record
  }

  const terminal: FindingStatus[] = ['RESOLVED', 'ACCEPTED_RISK', 'FALSE_POSITIVE'];

  if (failing) {
    if (terminal.includes(current)) {
      return { nextStatus: 'OPEN', keep: true, reason: 'regression_reopened' };
    }
    return { nextStatus: current, keep: true, reason: 'still_failing' };
  }

  // passing
  if (current === 'RESOLVED' || current === 'ACCEPTED_RISK' || current === 'FALSE_POSITIVE') {
    return { nextStatus: current, keep: true, reason: 'still_not_failing' };
  }
  return { nextStatus: 'RESOLVED', keep: true, reason: 'verified_resolved' };
}
