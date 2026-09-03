'use server';

import { revalidatePath } from 'next/cache';
import { redirect } from 'next/navigation';
import { z } from 'zod';
import { FINDING_STATUSES } from '@smb/shared';
import { prisma } from '@/lib/prisma';
import { isProd } from '@/lib/env';
import {
  AuthError,
  assertRole,
  loginUser,
  logoutUser,
  registerUser,
  requireContext,
} from '@/server/auth';
import { writeAudit } from '@/server/audit';
import { ingestScan } from '@/server/ingest';
import { generateReport } from '@/server/report';
import { buildDemoScan, demoAssetSpec } from '@/server/demo';
import { getAssetForOrg, getFindingForOrg } from '@/server/tenant';

type ActionState = { error?: string } | undefined;

const credentials = z.object({
  email: z.string().email(),
  password: z.string().min(10, 'Use at least 10 characters.'),
});

export async function registerAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const parsed = credentials
    .extend({ organizationName: z.string().min(2, 'Organization name is required.') })
    .safeParse(Object.fromEntries(form));
  if (!parsed.success) return { error: parsed.error.issues[0]?.message ?? 'Invalid input.' };
  try {
    await registerUser(parsed.data);
  } catch (err) {
    return { error: err instanceof AuthError ? err.message : 'Could not create the account.' };
  }
  redirect('/dashboard');
}

export async function loginAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const parsed = credentials.safeParse(Object.fromEntries(form));
  if (!parsed.success) return { error: 'Enter your email and password.' };
  try {
    await loginUser(parsed.data);
  } catch (err) {
    return { error: err instanceof AuthError ? err.message : 'Could not sign in.' };
  }
  redirect('/dashboard');
}

export async function logoutAction(): Promise<void> {
  await logoutUser();
  redirect('/login');
}

const assetInput = z.object({
  name: z.string().min(1).max(120),
  platform: z.enum(['windows', 'linux']),
  description: z.string().max(500).optional(),
});

export async function addAssetAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const ctx = await requireContext();
  try {
    assertRole(ctx, ['OWNER', 'ADMIN']);
  } catch {
    return { error: 'You need admin rights to add assets.' };
  }
  const parsed = assetInput.safeParse(Object.fromEntries(form));
  if (!parsed.success) return { error: parsed.error.issues[0]?.message ?? 'Invalid input.' };
  try {
    const asset = await prisma.asset.create({
      data: {
        organizationId: ctx.organizationId,
        name: parsed.data.name.trim(),
        platform: parsed.data.platform,
        description: parsed.data.description?.trim() || null,
        isDemo: ctx.isDemoOrg,
      },
    });
    await writeAudit({
      organizationId: ctx.organizationId,
      userId: ctx.userId,
      action: 'asset.created',
      detail: { assetId: asset.id, name: asset.name },
    });
  } catch {
    return { error: 'An asset with that name already exists.' };
  }
  revalidatePath('/assets');
  revalidatePath('/dashboard');
  return {};
}

/** Run (or re-run) a demo scan for one demo asset. `fix` resolves those checks. */
export async function runDemoScanAction(assetId: string, fixCheckIds: string[] = []): Promise<ActionState> {
  const ctx = await requireContext();
  if (!ctx.isDemoOrg) return { error: 'Demo scans are only available in a demo organization.' };
  const asset = await getAssetForOrg(ctx.organizationId, assetId);
  const spec = demoAssetSpec(asset.name);
  if (!spec) return { error: 'No demo scenario for this asset.' };
  const result = buildDemoScan(spec, { fixCheckIds });
  try {
    await ingestScan(ctx, { assetId, source: 'DEMO', rawResult: result });
  } catch (err) {
    return { error: err instanceof Error ? err.message : 'Demo scan failed.' };
  }
  revalidatePath('/dashboard');
  revalidatePath('/assets');
  revalidatePath('/findings');
  revalidatePath(`/assets/${assetId}`);
  return {};
}

/** Re-scan a single demo finding, marking its check as fixed so it verifies as RESOLVED. */
export async function rescanFindingAction(findingId: string): Promise<ActionState> {
  const ctx = await requireContext();
  const finding = await getFindingForOrg(ctx.organizationId, findingId);
  if (!ctx.isDemoOrg) {
    return { error: 'Live re-scan requires uploading a fresh scan from the agent. See docs/SCANNER.md.' };
  }
  const spec = demoAssetSpec(finding.asset.name);
  if (!spec) return { error: 'No demo scenario for this asset.' };
  const result = buildDemoScan(spec, { fixCheckIds: [finding.checkId] });
  try {
    await ingestScan(ctx, { assetId: finding.assetId, source: 'DEMO', rawResult: result });
  } catch (err) {
    return { error: err instanceof Error ? err.message : 'Re-scan failed.' };
  }
  revalidatePath(`/findings/${findingId}`);
  revalidatePath('/findings');
  revalidatePath('/dashboard');
  return {};
}

const statusInput = z.object({
  findingId: z.string(),
  status: z.enum(FINDING_STATUSES),
  note: z.string().max(500).optional(),
});

export async function updateFindingStatusAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const ctx = await requireContext();
  const parsed = statusInput.safeParse(Object.fromEntries(form));
  if (!parsed.success) return { error: 'Invalid status change.' };
  const finding = await getFindingForOrg(ctx.organizationId, parsed.data.findingId);
  if (finding.status === parsed.data.status) return {};
  await prisma.$transaction([
    prisma.finding.update({
      where: { id: finding.id },
      data: {
        previousStatus: finding.status,
        status: parsed.data.status,
        note: parsed.data.note?.trim() || finding.note,
        resolvedAt: parsed.data.status === 'RESOLVED' ? new Date() : null,
        resolvedById: parsed.data.status === 'RESOLVED' ? ctx.userId : null,
      },
    }),
    prisma.findingEvent.create({
      data: {
        findingId: finding.id,
        fromStatus: finding.status,
        toStatus: parsed.data.status,
        reason: 'user_status_change',
        actor: ctx.userId,
      },
    }),
  ]);
  await writeAudit({
    organizationId: ctx.organizationId,
    userId: ctx.userId,
    action: 'finding.status_changed',
    detail: { findingId: finding.id, from: finding.status, to: parsed.data.status },
  });
  revalidatePath(`/findings/${finding.id}`);
  revalidatePath('/findings');
  revalidatePath('/dashboard');
  return {};
}

export async function generateReportAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const ctx = await requireContext();
  try {
    assertRole(ctx, ['OWNER', 'ADMIN']);
  } catch {
    return { error: 'You need admin rights to generate reports.' };
  }
  const includeAi = form.get('includeAi') === 'on';
  const { id } = await generateReport(ctx, { includeAiNarrative: includeAi });
  revalidatePath('/reports');
  redirect(`/reports/${id}`);
}

export async function explainFindingAction(
  findingId: string,
): Promise<{ text: string; degraded: boolean } | { error: string }> {
  const ctx = await requireContext();
  const finding = await getFindingForOrg(ctx.organizationId, findingId);
  const { buildAiInput, generateArtifact, narrowToFinding } = await import('@/server/ai');
  const input = await buildAiInput(ctx.organizationId, ctx.organizationName, ctx.isDemoOrg);
  const res = await generateArtifact('finding-explanation', narrowToFinding(input, finding.id));
  return { text: res.text, degraded: res.degraded };
}

export async function executiveSummaryAction(): Promise<{ text: string; degraded: boolean }> {
  const ctx = await requireContext();
  const { buildAiInput, generateArtifact } = await import('@/server/ai');
  const input = await buildAiInput(ctx.organizationId, ctx.organizationName, ctx.isDemoOrg);
  return generateArtifact('executive-summary', input);
}

/** Local-only convenience: sign into the seeded demo org. */
export async function demoLoginAction(): Promise<void> {
  if (isProd) redirect('/login');
  const demo = await prisma.user.findFirst({
    where: { memberships: { some: { organization: { isDemo: true } } } },
    orderBy: { createdAt: 'asc' },
  });
  if (!demo) redirect('/login?demo=missing');
  const { createSession } = await import('@/server/auth/session');
  await createSession({ userId: demo.id, email: demo.email });
  redirect('/dashboard');
}
