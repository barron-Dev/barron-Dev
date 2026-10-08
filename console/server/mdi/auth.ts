import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import { NextRequest } from 'next/server';

export function mdiServerClient(): SupabaseClient {
  return createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!,
    { auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false } },
  );
}

export async function requireMdiClearance(req: NextRequest) {
  const token = req.headers.get('authorization')?.replace(/^Bearer\s+/i, '').trim();
  if (!token) throw new Error('unauthorized');
  const sb = mdiServerClient();
  const { data: { user }, error } = await sb.auth.getUser(token);
  if (error || !user) throw new Error('unauthorized');
  const { data: roles, error: roleErr } = await sb.from('user_roles').select('role').eq('user_id', user.id);
  if (roleErr) throw roleErr;
  const allowed = new Set(['mdi_investigator', 'mdi_supervisor', 'admin']);
  if (!(roles ?? []).some((r: any) => allowed.has(r.role))) throw new Error('mdi_clearance_required');
  return { sb, user };
}

export function authError(e: unknown) {
  const m = e instanceof Error ? e.message : String(e);
  return m === 'unauthorized'
    ? { status: 401, error: m }
    : m === 'mdi_clearance_required'
      ? { status: 403, error: m }
      : { status: 500, error: 'mdi_internal_error' };
}
