import { execFile } from 'node:child_process';
import type { CollectorOutput } from '@smb/checks';

/**
 * Run ONE fixed command with a fixed argument list. No shell, so there is no
 * interpolation or injection surface. Every collector in this package uses this
 * and nothing else — the scanner cannot run arbitrary commands.
 */
export function runCommand(
  file: string,
  args: string[],
  opts: { timeoutMs?: number; maxBuffer?: number } = {},
): Promise<CollectorOutput> {
  const timeoutMs = opts.timeoutMs ?? 15_000;
  const maxBuffer = opts.maxBuffer ?? 1024 * 1024;
  return new Promise((resolve) => {
    execFile(
      file,
      args,
      { timeout: timeoutMs, maxBuffer, windowsHide: true, shell: false },
      (err, stdout, stderr) => {
        const text = String(stdout ?? '').trim();
        if (err) {
          const reason =
            (err as NodeJS.ErrnoException).code === 'ENOENT'
              ? `command not found: ${file}`
              : `${file} exited with ${(err as { code?: number }).code ?? 'error'}`;
          // Some tools write useful data to stdout even on non-zero exit.
          resolve({ ok: text.length > 0, text, error: text ? undefined : `${reason} ${String(stderr ?? '').trim()}`.trim() });
          return;
        }
        resolve({ ok: true, text });
      },
    );
  });
}

/** A PowerShell one-liner, run without a profile and non-interactively. */
export function runPowerShell(script: string, timeoutMs = 20_000): Promise<CollectorOutput> {
  return runCommand(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script],
    { timeoutMs },
  );
}

import { readFile } from 'node:fs/promises';

/** Read a file as a collector (used for sshd_config, /etc/passwd, etc.). */
export async function readTextFile(path: string): Promise<CollectorOutput> {
  try {
    const text = (await readFile(path, 'utf8')).trim();
    return { ok: true, text };
  } catch (err) {
    return { ok: false, text: '', error: `cannot read ${path}: ${(err as Error).message}` };
  }
}
