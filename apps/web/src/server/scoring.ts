import 'server-only';
import { getCheck, getCheckMeta, listChecks } from '@smb/checks';
import { EFFORT_MINUTES } from '@smb/shared';
import { computeOrgScore, prioritize, type PrioritizableFinding, type ScoredFinding } from '@smb/risk-engine';
import { computeCoverage, type CheckAssessment } from '@smb/compliance';
import { prisma } from '@/lib/prisma';
import { activeFindingsForOrg } from '@/server/tenant';

export interface OrgPosture {
  score: number | null;
  band: string | null;
  assetCount: number;
  counts: { critical: number; high: number; medium: number; low: number };
  categories: { category: string; score: number | null; activeFindings: number }[];
  contributions: {
    checkId: string;
    checkName: string;
    severity: string;
    affectedAssets: number;
    pointsDeducted: number;
  }[];
  priorities: {
    rank: number;
    checkId: string;
    checkName: string;
    severity: string;
    category: string;
    affectedAssets: number;
    effortLabel: string;
  }[];
}

/** Recompute the whole org posture from its current active findings. */
export async function computePosture(organizationId: string): Promise<OrgPosture> {
  const [assets, active] = await Promise.all([
    prisma.asset.findMany({ where: { organizationId, status: 'ACTIVE' }, select: { id: true } }),
    activeFindingsForOrg(organizationId),
  ]);
  const assetIds = assets.map((a) => a.id);

  const scored: ScoredFinding[] = active.map((f) => ({
    checkId: f.checkId,
    severity: f.severity,
    category: f.category as ScoredFinding['category'],
    assetId: f.assetId,
    status: f.status,
  }));

  const org = computeOrgScore(scored, assetIds);

  const prioritizable: PrioritizableFinding[] = active.map((f) => {
    const check = getCheck(f.checkId);
    return {
      checkId: f.checkId,
      checkName: check?.name ?? f.checkId,
      severity: f.severity,
      category: f.category as PrioritizableFinding['category'],
      assetId: f.assetId,
      status: f.status,
      effortMinutes: check ? EFFORT_MINUTES[check.remediation.effort] : 30,
      isError: f.lastStatusRaw === 'ERROR',
    };
  });
  const ranked = prioritize(prioritizable, assetIds.length);

  return {
    score: org.score,
    band: org.band,
    assetCount: org.assetCount,
    counts: {
      critical: org.counts.CRITICAL,
      high: org.counts.HIGH,
      medium: org.counts.MEDIUM,
      low: org.counts.LOW,
    },
    categories: org.categories.map((c) => ({
      category: c.category,
      score: c.score,
      activeFindings: c.activeFindings,
    })),
    contributions: org.contributions.map((c) => ({
      checkId: c.checkId,
      checkName: getCheck(c.checkId)?.name ?? c.checkId,
      severity: c.severity,
      affectedAssets: c.affectedAssets,
      pointsDeducted: c.pointsDeducted,
    })),
    priorities: ranked.map((r) => ({
      rank: r.rank,
      checkId: r.checkId,
      checkName: r.checkName,
      severity: r.severity,
      category: r.category,
      affectedAssets: r.affectedAssets,
      effortLabel: getCheck(r.checkId)?.remediation.effort ?? 'unknown',
    })),
  };
}

/** Compliance coverage for the org, from which checks have run and which are failing. */
export async function computeOrgCoverage(organizationId: string) {
  const [ranAny, failingNow] = await Promise.all([
    prisma.scanResult.findMany({
      where: { scan: { organizationId } },
      select: { checkId: true },
      distinct: ['checkId'],
    }),
    activeFindingsForOrg(organizationId),
  ]);
  const failing = new Set(failingNow.map((f) => f.checkId));
  const assessed = new Set(ranAny.map((r) => r.checkId));
  const assessments: CheckAssessment[] = listChecks().map((c) => ({
    checkId: c.id,
    assessed: assessed.has(c.id),
    failing: failing.has(c.id),
  }));
  return computeCoverage(assessments);
}

/** Authoritative metadata for a check id (throws on unknown — used at ingestion). */
export function authoritativeMeta(checkId: string) {
  return getCheckMeta(checkId);
}
