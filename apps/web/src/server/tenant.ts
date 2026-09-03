import 'server-only';
import { prisma } from '@/lib/prisma';
import { NotFoundError } from '@/server/http';

/**
 * Every organization-owned read/write goes through one of these helpers, and
 * every helper requires `organizationId`. There is deliberately NO function
 * that loads an org-owned row by id alone — that is what prevents cross-tenant
 * access (see THREAT_MODEL T1/T2 and the isolation tests).
 */

export async function getAssetForOrg(organizationId: string, assetId: string) {
  const asset = await prisma.asset.findFirst({ where: { id: assetId, organizationId } });
  if (!asset) throw new NotFoundError('Asset not found.');
  return asset;
}

export function listAssetsForOrg(
  organizationId: string,
  filter?: { platform?: 'windows' | 'linux'; status?: 'ACTIVE' | 'ARCHIVED' },
) {
  return prisma.asset.findMany({
    where: {
      organizationId,
      ...(filter?.platform ? { platform: filter.platform } : {}),
      ...(filter?.status ? { status: filter.status } : {}),
    },
    orderBy: { name: 'asc' },
  });
}

export async function getFindingForOrg(organizationId: string, findingId: string) {
  const finding = await prisma.finding.findFirst({
    where: { id: findingId, organizationId },
    include: { asset: true, events: { orderBy: { createdAt: 'desc' } } },
  });
  if (!finding) throw new NotFoundError('Finding not found.');
  return finding;
}

export function listFindingsForOrg(
  organizationId: string,
  filter?: {
    severity?: string;
    category?: string;
    status?: string;
    assetId?: string;
    platform?: 'windows' | 'linux';
  },
) {
  return prisma.finding.findMany({
    where: {
      organizationId,
      ...(filter?.severity ? { severity: filter.severity as never } : {}),
      ...(filter?.category ? { category: filter.category } : {}),
      ...(filter?.status ? { status: filter.status as never } : {}),
      ...(filter?.assetId ? { assetId: filter.assetId } : {}),
      ...(filter?.platform ? { asset: { platform: filter.platform } } : {}),
    },
    include: { asset: true },
    orderBy: [{ severity: 'asc' }, { lastDetectedAt: 'desc' }],
  });
}

/** Active findings (those that count against the score) for the whole org. */
export function activeFindingsForOrg(organizationId: string) {
  return prisma.finding.findMany({
    where: { organizationId, status: { notIn: ['RESOLVED', 'ACCEPTED_RISK', 'FALSE_POSITIVE'] } },
    include: { asset: true },
  });
}

export async function getScanForOrg(organizationId: string, scanId: string) {
  const scan = await prisma.scan.findFirst({
    where: { id: scanId, organizationId },
    include: { asset: true, results: true },
  });
  if (!scan) throw new NotFoundError('Scan not found.');
  return scan;
}

export function listScansForOrg(organizationId: string, assetId?: string) {
  return prisma.scan.findMany({
    where: { organizationId, ...(assetId ? { assetId } : {}) },
    include: { asset: true },
    orderBy: { createdAt: 'desc' },
    take: 100,
  });
}

export async function getReportForOrg(organizationId: string, reportId: string) {
  const report = await prisma.report.findFirst({ where: { id: reportId, organizationId } });
  if (!report) throw new NotFoundError('Report not found.');
  return report;
}

export function listReportsForOrg(organizationId: string) {
  return prisma.report.findMany({
    where: { organizationId },
    orderBy: { createdAt: 'desc' },
  });
}

export function listAuditForOrg(organizationId: string, take = 100) {
  return prisma.auditLog.findMany({
    where: { organizationId },
    orderBy: { createdAt: 'desc' },
    take,
  });
}
