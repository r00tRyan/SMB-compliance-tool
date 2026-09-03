/**
 * In-memory fixed-window rate limiter. Per-instance only; adequate for the
 * single-instance MVP. Swap the Map for Redis behind this same interface later.
 */
interface Window {
  count: number;
  resetAt: number;
}

const buckets = new Map<string, Window>();

export interface RateLimitResult {
  ok: boolean;
  remaining: number;
  resetAt: number;
}

export function rateLimit(key: string, limit: number, windowMs: number): RateLimitResult {
  const now = Date.now();
  const existing = buckets.get(key);
  if (!existing || existing.resetAt <= now) {
    const w = { count: 1, resetAt: now + windowMs };
    buckets.set(key, w);
    return { ok: true, remaining: limit - 1, resetAt: w.resetAt };
  }
  existing.count += 1;
  return { ok: existing.count <= limit, remaining: Math.max(0, limit - existing.count), resetAt: existing.resetAt };
}

/** test helper */
export function __resetRateLimits(): void {
  buckets.clear();
}
