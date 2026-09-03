import { describe, expect, it } from 'vitest';
import { decideTransition } from '../lifecycle';

describe('decideTransition — finding lifecycle', () => {
  it('opens a new finding on first FAIL', () => {
    expect(decideTransition(null, 'FAIL')).toMatchObject({ nextStatus: 'OPEN', keep: true, reason: 'new_finding' });
  });

  it('opens a new finding on first WARN (a below-baseline configuration)', () => {
    expect(decideTransition(null, 'WARN')?.nextStatus).toBe('OPEN');
  });

  it('records nothing for a PASS with no prior finding', () => {
    expect(decideTransition(null, 'PASS')).toBeNull();
  });

  it('keeps an OPEN finding OPEN while it still fails', () => {
    expect(decideTransition('OPEN', 'FAIL')).toMatchObject({ nextStatus: 'OPEN', reason: 'still_failing' });
  });

  it('preserves a user-set ACKNOWLEDGED/IN_PROGRESS status while still failing', () => {
    expect(decideTransition('ACKNOWLEDGED', 'FAIL')?.nextStatus).toBe('ACKNOWLEDGED');
    expect(decideTransition('IN_PROGRESS', 'WARN')?.nextStatus).toBe('IN_PROGRESS');
  });

  it('RESOLVES an open finding when the re-scan shows PASS (the verify loop)', () => {
    expect(decideTransition('OPEN', 'PASS')).toMatchObject({ nextStatus: 'RESOLVED', reason: 'verified_resolved' });
    expect(decideTransition('IN_PROGRESS', 'NOT_APPLICABLE')?.nextStatus).toBe('RESOLVED');
  });

  it('REOPENS a resolved finding if the problem comes back (regression)', () => {
    expect(decideTransition('RESOLVED', 'FAIL')).toMatchObject({ nextStatus: 'OPEN', reason: 'regression_reopened' });
  });

  it('keeps ACCEPTED_RISK / FALSE_POSITIVE sticky while still passing', () => {
    expect(decideTransition('ACCEPTED_RISK', 'PASS')?.nextStatus).toBe('ACCEPTED_RISK');
    expect(decideTransition('FALSE_POSITIVE', 'PASS')?.nextStatus).toBe('FALSE_POSITIVE');
  });

  it('reopens ACCEPTED_RISK / FALSE_POSITIVE on a new failure', () => {
    expect(decideTransition('ACCEPTED_RISK', 'FAIL')?.nextStatus).toBe('OPEN');
    expect(decideTransition('FALSE_POSITIVE', 'FAIL')?.nextStatus).toBe('OPEN');
  });

  it('treats ERROR (could-not-assess) as no change', () => {
    expect(decideTransition(null, 'ERROR')).toBeNull();
    expect(decideTransition('OPEN', 'ERROR')).toMatchObject({ nextStatus: 'OPEN', reason: 'observation_error_no_change' });
    expect(decideTransition('RESOLVED', 'ERROR')?.nextStatus).toBe('RESOLVED');
  });

  it('models a full remediate → re-scan → verified → regression cycle', () => {
    let status = decideTransition(null, 'FAIL')!.nextStatus; // OPEN
    expect(status).toBe('OPEN');
    status = decideTransition(status, 'FAIL')!.nextStatus; // still OPEN
    status = decideTransition(status, 'PASS')!.nextStatus; // RESOLVED
    expect(status).toBe('RESOLVED');
    status = decideTransition(status, 'FAIL')!.nextStatus; // regression → OPEN
    expect(status).toBe('OPEN');
  });
});
