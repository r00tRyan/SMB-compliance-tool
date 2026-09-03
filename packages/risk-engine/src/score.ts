import { CATEGORIES, INACTIVE_FINDING_STATUSES } from '@smb/shared';
import type { Category, FindingStatus, Severity } from '@smb/shared';
import { bandFor, clamp, SEVERITY_PENALTY, type ScoreBand } from './model.js';

/** One active finding row, reduced to what scoring needs. */
export interface ScoredFinding {
  checkId: string;
  severity: Severity;
  category: Category;
  assetId: string;
  status: FindingStatus;
}

export interface CategoryScore {
  category: Category;
  score: number | null;
  activeFindings: number;
}

/** How many points a specific check (aggregated across assets) removed. */
export interface ScoreContribution {
  checkId: string;
  severity: Severity;
  category: Category;
  affectedAssets: number;
  pointsDeducted: number;
}

export interface OrgScore {
  /** null when there are no assets yet (empty state). */
  score: number | null;
  band: ScoreBand | null;
  assetCount: number;
  /** Count of ACTIVE findings by severity. */
  counts: Record<Severity, number>;
  categories: CategoryScore[];
  /** Sorted desc by pointsDeducted — drives "why is my score NN". */
  contributions: ScoreContribution[];
}

const isActive = (s: FindingStatus): boolean => !INACTIVE_FINDING_STATUSES.includes(s);

const emptyCounts = (): Record<Severity, number> => ({
  CRITICAL: 0,
  HIGH: 0,
  MEDIUM: 0,
  LOW: 0,
  INFO: 0,
});

/**
 * Compute the organization score.
 *
 * Model (see SCORING.md):
 *  - Each asset starts at 100.
 *  - Each ACTIVE failing check on that asset deducts SEVERITY_PENALTY[severity].
 *  - Asset score = clamp(100 - sum(penalties), 0, 100).
 *  - Org score   = round(mean(asset scores)).
 *  - Category score is the same computation restricted to that category.
 *
 * The model is intentionally simple and fully explainable: every deducted
 * point traces to one finding.
 */
export function computeOrgScore(findings: ScoredFinding[], assetIds: string[]): OrgScore {
  const assetCount = assetIds.length;
  if (assetCount === 0) {
    return {
      score: null,
      band: null,
      assetCount: 0,
      counts: emptyCounts(),
      categories: CATEGORIES.map((c) => ({ category: c, score: null, activeFindings: 0 })),
      contributions: [],
    };
  }

  const active = findings.filter((f) => isActive(f.status));

  // Per-asset penalties (overall + per category).
  const assetPenalty = new Map<string, number>();
  const assetCategoryPenalty = new Map<string, Map<Category, number>>();
  for (const id of assetIds) {
    assetPenalty.set(id, 0);
    assetCategoryPenalty.set(id, new Map());
  }

  const counts = emptyCounts();
  const contribMap = new Map<string, ScoreContribution>();

  for (const f of active) {
    counts[f.severity] += 1;
    const penalty = SEVERITY_PENALTY[f.severity];

    if (assetPenalty.has(f.assetId)) {
      assetPenalty.set(f.assetId, (assetPenalty.get(f.assetId) ?? 0) + penalty);
      const catMap = assetCategoryPenalty.get(f.assetId)!;
      catMap.set(f.category, (catMap.get(f.category) ?? 0) + penalty);
    }

    const existing = contribMap.get(f.checkId);
    if (existing) {
      existing.affectedAssets += 1;
      existing.pointsDeducted += penalty;
    } else {
      contribMap.set(f.checkId, {
        checkId: f.checkId,
        severity: f.severity,
        category: f.category,
        affectedAssets: 1,
        pointsDeducted: penalty,
      });
    }
  }

  const assetScores = assetIds.map((id) => clamp(100 - (assetPenalty.get(id) ?? 0)));
  const score = Math.round(assetScores.reduce((a, b) => a + b, 0) / assetCount);

  const categories: CategoryScore[] = CATEGORIES.map((category) => {
    const perAsset = assetIds.map((id) => {
      const p = assetCategoryPenalty.get(id)?.get(category) ?? 0;
      return clamp(100 - p);
    });
    const catScore = Math.round(perAsset.reduce((a, b) => a + b, 0) / assetCount);
    const activeFindings = active.filter((f) => f.category === category).length;
    return { category, score: catScore, activeFindings };
  });

  const contributions = [...contribMap.values()].sort(
    (a, b) => b.pointsDeducted - a.pointsDeducted || a.checkId.localeCompare(b.checkId),
  );

  return { score, band: bandFor(score), assetCount, counts, categories, contributions };
}
