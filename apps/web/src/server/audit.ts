import 'server-only';
import { Prisma } from '@prisma/client';
import { prisma } from '@/lib/prisma';
import { logger } from '@/lib/logger';

const SECRETISH = /(password|token|secret|apikey|authorization)/i;

/**
 * Append an audit row. `detail` is a small bag — this strips any obviously
 * sensitive keys as a backstop so secrets never land in the audit log.
 */
export async function writeAudit(entry: {
  organizationId?: string | null;
  userId?: string | null;
  action: string;
  detail?: Record<string, unknown>;
}): Promise<void> {
  const detail = entry.detail
    ? Object.fromEntries(
        Object.entries(entry.detail).filter(([k]) => !SECRETISH.test(k)),
      )
    : undefined;
  try {
    await prisma.auditLog.create({
      data: {
        organizationId: entry.organizationId ?? null,
        userId: entry.userId ?? null,
        action: entry.action,
        detail: (detail ?? undefined) as Prisma.InputJsonValue | undefined,
      },
    });
  } catch (err) {
    // Auditing must never break the primary action; log and move on.
    logger.error('audit write failed', { action: entry.action, err: String(err) });
  }
}
