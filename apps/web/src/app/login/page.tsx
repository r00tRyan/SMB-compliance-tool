import Link from 'next/link';
import { redirect } from 'next/navigation';
import { getActiveContext } from '@/server/auth';
import { loginAction, demoLoginAction } from '@/app/actions';
import { ActionForm, SubmitButton } from '@/components/form';
import { isProd } from '@/lib/env';

export const dynamic = 'force-dynamic';

export default async function LoginPage() {
  if (await getActiveContext()) redirect('/dashboard');
  return (
    <main className="mx-auto max-w-sm px-4 py-16">
      <h1 className="text-xl font-semibold">Sign in</h1>
      <p className="mt-1 text-sm text-muted">Security posture &amp; compliance readiness.</p>

      <div className="card mt-6">
        <ActionForm action={loginAction}>
          <label className="label" htmlFor="email">Email</label>
          <input id="email" name="email" type="email" autoComplete="email" className="input" required />
          <div className="h-3" />
          <label className="label" htmlFor="password">Password</label>
          <input id="password" name="password" type="password" autoComplete="current-password" className="input" required />
          <div className="mt-4">
            <SubmitButton>Sign in</SubmitButton>
          </div>
        </ActionForm>
      </div>

      <p className="mt-4 text-sm text-muted">
        No account? <Link className="text-brand" href="/register">Create one</Link>
      </p>

      {!isProd ? (
        <form action={demoLoginAction} className="mt-6">
          <button type="submit" className="btn-ghost w-full">Open the Acme Dental demo (local only)</button>
        </form>
      ) : null}
    </main>
  );
}
