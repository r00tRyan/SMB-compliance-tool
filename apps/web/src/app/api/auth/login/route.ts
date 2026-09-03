import { z } from 'zod';
import { loginUser, AuthError } from '@/server/auth';
import { apiError, apiOk, assertSameOrigin, parseJson, route } from '@/server/http';

export const dynamic = 'force-dynamic';

const schema = z.object({ email: z.string().email(), password: z.string().min(1) });

export function POST(req: Request) {
  return route(async () => {
    assertSameOrigin();
    const body = await parseJson(req, schema);
    try {
      await loginUser(body);
      return apiOk({ ok: true });
    } catch (err) {
      if (err instanceof AuthError) return apiError('unauthorized', err.message, 401);
      throw err;
    }
  });
}
