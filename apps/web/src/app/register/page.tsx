import Link from 'next/link';
import { redirect } from 'next/navigation';
import { getActiveContext } from '@/server/auth';
import { registerAction } from '@/app/actions';
import { ActionForm, SubmitButton } from '@/components/form';

export const dynamic = 'force-dynamic';

export default async function RegisterPage() {
  if (await getActiveContext()) redirect('/dashboard');
  return (
    <main className="mx-auto max-w-sm px-4 py-16">
      <h1 className="text-xl font-semibold">Create your account</h1>
      <p className="mt-1 text-sm text-muted">You&apos;ll be the owner of a new organization.</p>

      <div className="card mt-6">
        <ActionForm action={registerAction}>
          <label className="label" htmlFor="organizationName">Organization name</label>
          <input id="organizationName" name="organizationName" className="input" required />
          <div className="h-3" />
          <label className="label" htmlFor="email">Work email</label>
          <input id="email" name="email" type="email" autoComplete="email" className="input" required />
          <div className="h-3" />
          <label className="label" htmlFor="password">Password</label>
          <input id="password" name="password" type="password" autoComplete="new-password" className="input" required minLength={10} />
          <p className="mt-1 text-xs text-muted">At least 10 characters.</p>
          <div className="mt-4">
            <SubmitButton>Create account</SubmitButton>
          </div>
        </ActionForm>
      </div>

      <p className="mt-4 text-sm text-muted">
        Already have an account? <Link className="text-brand" href="/login">Sign in</Link>
      </p>
    </main>
  );
}
