"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { clearApiToken } from "../lib/api";
import { supabase } from "../lib/supabase-public";

export function AuthActions() {
  const router = useRouter();
  const [busy, setBusy] = useState(false);

  async function signOut() {
    if (busy) return;
    setBusy(true);
    try { await supabase.auth.signOut(); } finally {
      clearApiToken();
      sessionStorage.removeItem("cyclothone_refresh_token");
      sessionStorage.removeItem("cyclothone_auth_entry");
      sessionStorage.removeItem("cyclothone_pending_profile");
      sessionStorage.removeItem("cyclothone_pending_organization");
      router.replace("/login");
    }
  }

  return <button type="button" onClick={() => void signOut()} disabled={busy} className="border border-[#2a3646] px-3 py-2 text-[10px] text-[#8a97a8] disabled:opacity-50">{busy ? "Signing out…" : "Sign out"}</button>;
}
