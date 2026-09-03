import { logoutUser } from '@/server/auth';
import { apiOk, assertSameOrigin, route } from '@/server/http';

export const dynamic = 'force-dynamic';

export function POST() {
  return route(async () => {
    assertSameOrigin();
    await logoutUser();
    return apiOk({ ok: true });
  });
}
