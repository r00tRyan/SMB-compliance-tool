'use client';

import { useFormState, useFormStatus } from 'react-dom';
import type { ReactNode } from 'react';

type ActionState = { error?: string } | undefined;
type Action = (prev: ActionState, form: FormData) => Promise<ActionState>;

export function SubmitButton({ children }: { children: ReactNode }) {
  const { pending } = useFormStatus();
  return (
    <button type="submit" className="btn-primary" disabled={pending} aria-busy={pending}>
      {pending ? 'Working…' : children}
    </button>
  );
}

export function ActionForm({
  action,
  children,
  className,
}: {
  action: Action;
  children: ReactNode;
  className?: string;
}) {
  const [state, formAction] = useFormState(action, undefined);
  return (
    <form action={formAction} className={className}>
      {state?.error ? (
        <p className="mb-3 rounded-lg bg-red-50 px-3 py-2 text-sm text-sev-critical">{state.error}</p>
      ) : null}
      {children}
    </form>
  );
}
