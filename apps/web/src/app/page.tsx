import { redirect } from 'next/navigation';
import { getActiveContext } from '@/server/auth';

export const dynamic = 'force-dynamic';

export default async function Home() {
  const ctx = await getActiveContext();
  redirect(ctx ? '/dashboard' : '/login');
}
