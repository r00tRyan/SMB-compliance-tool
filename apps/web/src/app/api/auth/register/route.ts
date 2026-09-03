import { z } from 'zod';
import { registerUser, AuthError } from '@/server/auth';
import { apiError, apiOk, assertSameOrigin, parseJson, route } from '@/server/http';

export const dynamic = 'force-dynamic';

const schema = z.object({
  email: z.string().email(),
  password: z.string().min(10),
  organizationName: z.string().min(2).max(120),
});

export function POST(req: Request) {
  return route(async () => {
    assertSameOrigin();
    const body = await parseJson(req, schema);
    try {
      const res = await registerUser(body);
      return apiOk({ userId: res.userId, organizationId: res.organizationId }, 201);
    } catch (err) {
      if (err instanceof AuthError) return apiError('conflict', err.message, 409);
      throw err;
    }
  });
}
