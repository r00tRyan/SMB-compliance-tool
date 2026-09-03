import 'server-only';
import { redirect } from 'next/navigation';
import type { Role } from '@prisma/client';
import { prisma } from '@/lib/prisma';
import { writeAudit } from '@/server/audit';
import { hashPassword, verifyPassword } from './password';
import { createSession, readSession, clearSession } from './session';

export class AuthError extends Error {}

export interface ActiveContext {
  userId: string;
  email: string;
  organizationId: string;
  organizationName: string;
  isDemoOrg: boolean;
  role: Role;
}

/** Register a new user + their first organization (they become OWNER). */
export async function registerUser(input: {
  email: string;
  password: string;
  organizationName: string;
}): Promise<{ userId: string; organizationId: string }> {
  const email = input.email.trim().toLowerCase();
  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) throw new AuthError('An account with that email already exists.');

  const passwordHash = await hashPassword(input.password);
  const result = await prisma.$transaction(async (tx) => {
    const user = await tx.user.create({ data: { email, passwordHash } });
    const org = await tx.organization.create({ data: { name: input.organizationName.trim() } });
    await tx.membership.create({
      data: { userId: user.id, organizationId: org.id, role: 'OWNER' },
    });
    return { userId: user.id, organizationId: org.id };
  });

  await createSession({ userId: result.userId, email });
  await writeAudit({ organizationId: result.organizationId, userId: result.userId, action: 'organization.created' });
  await writeAudit({ organizationId: result.organizationId, userId: result.userId, action: 'auth.login' });
  return result;
}

/** Verify credentials and start a session. Generic error on failure (no enumeration). */
export async function loginUser(input: { email: string; password: string }): Promise<void> {
  const email = input.email.trim().toLowerCase();
  const user = await prisma.user.findUnique({ where: { email } });
  const ok = user ? await verifyPassword(user.passwordHash, input.password) : false;
  if (!user || !ok) throw new AuthError('Incorrect email or password.');
  await createSession({ userId: user.id, email });
  const membership = await prisma.membership.findFirst({ where: { userId: user.id } });
  await writeAudit({ organizationId: membership?.organizationId, userId: user.id, action: 'auth.login' });
}

export async function logoutUser(): Promise<void> {
  const session = await readSession();
  if (session) {
    const m = await prisma.membership.findFirst({ where: { userId: session.userId } });
    await writeAudit({ organizationId: m?.organizationId, userId: session.userId, action: 'auth.logout' });
  }
  clearSession();
}

/** Resolve the caller's active org context or null. */
export async function getActiveContext(): Promise<ActiveContext | null> {
  const session = await readSession();
  if (!session) return null;
  const membership = await prisma.membership.findFirst({
    where: { userId: session.userId },
    orderBy: { createdAt: 'asc' },
    include: { organization: true },
  });
  if (!membership) return null;
  return {
    userId: session.userId,
    email: session.email,
    organizationId: membership.organizationId,
    organizationName: membership.organization.name,
    isDemoOrg: membership.organization.isDemo,
    role: membership.role,
  };
}

/** Server-component / route guard: redirects to /login when unauthenticated. */
export async function requireContext(): Promise<ActiveContext> {
  const ctx = await getActiveContext();
  if (!ctx) redirect('/login');
  return ctx;
}

/** API guard: throws AuthError instead of redirecting. */
export async function requireApiContext(): Promise<ActiveContext> {
  const ctx = await getActiveContext();
  if (!ctx) throw new AuthError('Authentication required.');
  return ctx;
}

export function assertRole(ctx: ActiveContext, allowed: Role[]): void {
  if (!allowed.includes(ctx.role)) throw new AuthError('You do not have permission to do that.');
}
