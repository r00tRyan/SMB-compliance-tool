'use client';

import { useState, useTransition } from 'react';
import { useRouter } from 'next/navigation';

export function AsyncButton({
  action,
  children,
  className = 'btn-primary',
  confirm,
}: {
  action: () => Promise<{ error?: string } | undefined>;
  children: React.ReactNode;
  className?: string;
  confirm?: string;
}) {
  const [pending, start] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const router = useRouter();

  return (
    <span className="inline-flex flex-col gap-1">
      <button
        type="button"
        className={className}
        disabled={pending}
        onClick={() => {
          if (confirm && !window.confirm(confirm)) return;
          setError(null);
          start(async () => {
            const res = await action();
            if (res?.error) setError(res.error);
            else router.refresh();
          });
        }}
      >
        {pending ? 'Working…' : children}
      </button>
      {error ? <span className="text-xs text-sev-critical">{error}</span> : null}
    </span>
  );
}
