import { headers } from 'next/headers';
import { NextResponse } from 'next/server';
import { z } from 'zod';
import { AuthError } from '@/server/auth';
import { logger } from '@/lib/logger';

export interface ApiErrorShape {
  error: { code: string; message: string };
}

export function apiError(code: string, message: string, status: number): NextResponse<ApiErrorShape> {
  return NextResponse.json({ error: { code, message } }, { status });
}

export function apiOk<T>(data: T, status = 200): NextResponse<T> {
  return NextResponse.json(data, { status });
}

/**
 * State-changing routes must be same-origin: the browser sends a session cookie
 * automatically, so we also require Origin / Sec-Fetch-Site to be same-origin.
 */
export function assertSameOrigin(): void {
  const h = headers();
  const site = h.get('sec-fetch-site');
  if (site && site !== 'same-origin' && site !== 'none') {
    throw new CsrfError();
  }
  const origin = h.get('origin');
  const host = h.get('host');
  if (origin && host) {
    try {
      if (new URL(origin).host !== host) throw new CsrfError();
    } catch {
      throw new CsrfError();
    }
  }
}

export class CsrfError extends Error {}

export async function parseJson<S extends z.ZodTypeAny>(
  req: Request,
  schema: S,
  maxBytes = 256 * 1024,
): Promise<z.infer<S>> {
  const raw = await req.text();
  if (raw.length > maxBytes) throw new PayloadTooLargeError();
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    throw new BadInputError('Request body is not valid JSON.');
  }
  const parsed = schema.safeParse(json);
  if (!parsed.success) {
    throw new BadInputError(parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; '));
  }
  return parsed.data;
}

export class BadInputError extends Error {}
export class PayloadTooLargeError extends Error {}
export class NotFoundError extends Error {}

/** Wrap a route handler so every known error maps to a safe response shape. */
export function route(handler: () => Promise<NextResponse>): Promise<NextResponse> {
  return handler().catch((err): NextResponse<ApiErrorShape> => {
    if (err instanceof AuthError) return apiError('unauthorized', err.message, 401);
    if (err instanceof CsrfError) return apiError('forbidden', 'Cross-origin request rejected.', 403);
    if (err instanceof NotFoundError) return apiError('not_found', err.message || 'Not found.', 404);
    if (err instanceof BadInputError) return apiError('bad_request', err.message, 400);
    if (err instanceof PayloadTooLargeError) return apiError('payload_too_large', 'Request body is too large.', 413);
    logger.error('unhandled route error', { err: err instanceof Error ? err.stack : String(err) });
    return apiError('internal_error', 'Something went wrong. Please try again.', 500);
  });
}
