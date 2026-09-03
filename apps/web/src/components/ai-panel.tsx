'use client';

import { useState, useTransition } from 'react';

export function AiPanel({
  label,
  action,
}: {
  label: string;
  action: () => Promise<{ text: string; degraded: boolean } | { error: string }>;
}) {
  const [pending, start] = useTransition();
  const [result, setResult] = useState<{ text: string; degraded: boolean } | null>(null);
  const [error, setError] = useState<string | null>(null);

  return (
    <div>
      <button
        type="button"
        className="btn-ghost"
        disabled={pending}
        onClick={() =>
          start(async () => {
            setError(null);
            const res = await action();
            if ('error' in res) setError(res.error);
            else setResult(res);
          })
        }
      >
        {pending ? 'Generating…' : label}
      </button>
      {error ? <p className="mt-2 text-sm text-sev-critical">{error}</p> : null}
      {result ? (
        <div className="mt-3 rounded-lg border border-line bg-slate-50 p-3 text-sm whitespace-pre-wrap">
          {result.degraded ? (
            <p className="mb-2 text-xs font-medium text-amber-700">
              AI reporting is temporarily unavailable — showing a deterministic summary. Your findings are unaffected.
            </p>
          ) : (
            <p className="mb-2 text-xs font-medium text-muted">AI-generated · review before sharing</p>
          )}
          {result.text}
        </div>
      ) : null}
    </div>
  );
}
