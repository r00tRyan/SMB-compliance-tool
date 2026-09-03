import 'server-only';
import { cookies } from 'next/headers';
import { SignJWT, jwtVerify } from 'jose';
import { env, cookieSecure } from '@/lib/env';

const COOKIE = 'smb_session';
const MAX_AGE_SECONDS = 60 * 60 * 12; // 12h idle lifetime
const key = new TextEncoder().encode(env.AUTH_SECRET);

export interface SessionPayload {
  userId: string;
  email: string;
}

export async function createSession(payload: SessionPayload): Promise<void> {
  const token = await new SignJWT({ ...payload })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(`${MAX_AGE_SECONDS}s`)
    .sign(key);

  cookies().set(COOKIE, token, {
    httpOnly: true,
    secure: cookieSecure,
    sameSite: 'lax',
    path: '/',
    maxAge: MAX_AGE_SECONDS,
  });
}

export async function readSession(): Promise<SessionPayload | null> {
  const token = cookies().get(COOKIE)?.value;
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, key);
    if (typeof payload.userId === 'string' && typeof payload.email === 'string') {
      return { userId: payload.userId, email: payload.email };
    }
    return null;
  } catch {
    return null;
  }
}

export function clearSession(): void {
  cookies().delete(COOKIE);
}
