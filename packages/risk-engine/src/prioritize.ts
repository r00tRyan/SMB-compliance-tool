import { INACTIVE_FINDING_STATUSES } from '@smb/shared';
import type { Category, FindingStatus, Severity } from '@smb/shared';
import {
  effortDivisor,
  EXPOSURE_FACTOR,
  LOW_CONFIDENCE_FACTOR,
  SEVERITY_PRIORITY_WEIGHT,
} from './model.js';

export interface PrioritizableFinding {
  checkId: string;
  checkName: string;
  severity: Severity;
  category: Category;
  assetId: string;
  status: FindingStatus;
  effortMinutes: number;
  /** scanner returned ERROR for this check on this asset (low confidence). */
  isError?: boolean;
}

export interface PriorityItem {
  rank: number;
  checkId: string;
  checkName: string;
  severity: Severity;
  category: Category;
  affectedAssets: number;
  effortMinutes: number;
  priorityScore: number;
}

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

const isActive = (s: FindingStatus): boolean => !INACTIVE_FINDING_STATUSES.includes(s);

/**
 * Rank remediation work. Not a simple severity sort: it blends severity,
 * how many machines are affected, network exposure, confidence, and how easy
 * the fix is. See SCORING.md §Prioritization.
 *
 *   base       = SEVERITY_PRIORITY_WEIGHT[severity]
 *   coverage   = 0.5 + 0.5 * (affectedAssets / totalAssets)     range 0.5..1.0
 *   exposure   = EXPOSURE_FACTOR[category]
 *   confidence = 1.0, or 0.6 if every affected finding was a scanner ERROR
 *   priority   = base * coverage * exposure * confidence / effortDivisor(minEffort)
 */
export function prioritize(
  findings: PrioritizableFinding[],
  totalAssets: number,
): PriorityItem[] {
  const assets = Math.max(totalAssets, 1);
  const groups = new Map<string, PrioritizableFinding[]>();
  for (const f of findings) {
    if (!isActive(f.status)) continue;
    const list = groups.get(f.checkId) ?? [];
    list.push(f);
    groups.set(f.checkId, list);
  }

  const items: Omit<PriorityItem, 'rank'>[] = [];
  for (const [checkId, group] of groups) {
    const first = group[0]!;
    const affectedAssets = new Set(group.map((g) => g.assetId)).size;
    const effortMinutes = Math.min(...group.map((g) => g.effortMinutes));
    const base = SEVERITY_PRIORITY_WEIGHT[first.severity];
    const coverage = 0.5 + 0.5 * (affectedAssets / assets);
    const exposure = EXPOSURE_FACTOR[first.category];
    const confidence = group.every((g) => g.isError) ? LOW_CONFIDENCE_FACTOR : 1.0;
    const priorityScore =
      (base * coverage * exposure * confidence) / effortDivisor(effortMinutes);

    items.push({
      checkId,
      checkName: first.checkName,
      severity: first.severity,
      category: first.category,
      affectedAssets,
      effortMinutes,
      priorityScore: Math.round(priorityScore * 100) / 100,
    });
  }

  return items
    .sort(
      (a, b) =>
        b.priorityScore - a.priorityScore ||
        SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
        b.affectedAssets - a.affectedAssets ||
        a.effortMinutes - b.effortMinutes ||
        a.checkId.localeCompare(b.checkId),
    )
    .map((item, i) => ({ rank: i + 1, ...item }));
}
