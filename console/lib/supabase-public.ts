import { createClient } from "@supabase/supabase-js";

const PROJECT_URL = "https://whcomikcftbousoqzeal.supabase.co";
const PUBLIC_KEY = "sb_publishable_3qKBAIdxxrDuE8gEGwJICg_5NEH3CVU";

export const SUPABASE_URL = (process.env.NEXT_PUBLIC_SUPABASE_URL || PROJECT_URL).replace(/\/$/, "");
export const SUPABASE_PUBLIC_KEY = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || PUBLIC_KEY;

export const supabase = createClient(SUPABASE_URL, SUPABASE_PUBLIC_KEY, {
  auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true },
});
