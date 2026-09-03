import Link from 'next/link';
import { requireContext } from '@/server/auth';
import { logoutAction } from '@/app/actions';
import { DemoBadge, NavLink } from '@/components/ui';
import { aiEnabled } from '@/server/ai';

export const dynamic = 'force-dynamic';

export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const ctx = await requireContext();
  return (
    <div className="min-h-screen">
      <header className="border-b border-line bg-white">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-3">
          <div className="flex items-center gap-1">
            <Link href="/dashboard" className="mr-2 font-semibold">
              SMB&nbsp;Security
            </Link>
            <NavLink href="/dashboard">Dashboard</NavLink>
            <NavLink href="/assets">Assets</NavLink>
            <NavLink href="/findings">Findings</NavLink>
            <NavLink href="/scans">Scans</NavLink>
            <NavLink href="/reports">Reports</NavLink>
            <NavLink href="/activity">Activity</NavLink>
          </div>
          <div className="flex items-center gap-3 text-sm">
            <span className="text-muted">
              {ctx.organizationName}
              {ctx.isDemoOrg ? <DemoBadge /> : null}
            </span>
            <form action={logoutAction}>
              <button className="btn-ghost py-1.5">Sign out</button>
            </form>
          </div>
        </div>
      </header>
      {!aiEnabled ? (
        <div className="bg-amber-50 text-amber-800 text-xs text-center py-1">
          AI reporting is not configured (ANTHROPIC_API_KEY unset). Deterministic summaries are used instead.
        </div>
      ) : null}
      <main className="mx-auto max-w-6xl px-4 py-6">{children}</main>
    </div>
  );
}
