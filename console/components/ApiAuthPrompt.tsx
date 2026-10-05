"use client";

import { useEffect, useState } from "react";
import { clearApiToken, setApiToken } from "../lib/api";
import { supabase } from "../lib/supabase-public";

export function ApiAuthPrompt() {
  const [open, setOpen] = useState(false);
  const [token, setToken] = useState("");

  useEffect(() => {
    const onRequired = async () => {
      const host = window.location.hostname;
      const customerSurface =
        host === "customers.cyclothone.online" ||
        host === "developers.cyclothone.online" ||
        host === "cyclothone.online" ||
        host === "www.cyclothone.online";

      if (customerSurface) {
        // A 401 can also mean that the requested backend route does not
        // authorize this customer surface. Never rotate a refresh token or
        // redirect merely because one endpoint returned 401.
        try {
          const current = await supabase.auth.getSession();
          if (current.data.session?.access_token) {
            setApiToken(current.data.session.access_token);
            return;
          }
        } catch {
          // Treat an auth-storage failure as unknown; do not manufacture logout.
          return;
        }

        clearApiToken();
        sessionStorage.removeItem("cyclothone_refresh_token");
        sessionStorage.removeItem("cyclothone_auth_entry");
        window.location.assign("/login");
        return;
      }
      setOpen(true);
    };
    window.addEventListener("cyclothone-auth-required", onRequired);
    return () => window.removeEventListener("cyclothone-auth-required", onRequired);
  }, []);

  if (!open) return null;

  function submit(event: React.FormEvent) {
    event.preventDefault();
    const value = token.trim();
    if (!value) return;
    setApiToken(value);
    setOpen(false);
    window.location.reload();
  }

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70 p-6" role="dialog" aria-modal="true" aria-label="API authentication required">
      <form onSubmit={submit} className="w-full max-w-md border border-[#2a3646] bg-[#0a0e14] p-6 text-[#e8eef6] shadow-2xl">
        <div className="text-[10px] uppercase tracking-[.16em] text-[#00d9ff]">Cyclothone API</div>
        <h2 className="mt-2 text-lg font-semibold">Authentication required</h2>
        <p className="mt-2 text-xs leading-5 text-[#8a97a8]">This internal service requires an access token. The token is kept in this browser session only.</p>
        <input autoFocus type="password" value={token} onChange={e => setToken(e.target.value)} placeholder="Access token" className="mt-4 h-10 w-full border border-[#2a3646] bg-[#030508] px-3 font-mono text-xs" />
        <div className="mt-4 flex justify-end gap-2"><button type="button" onClick={() => setOpen(false)} className="h-9 px-4 text-xs text-[#8a97a8]">Cancel</button><button type="submit" disabled={!token.trim()} className="h-9 border border-[#00d9ff] px-4 text-xs text-[#00d9ff] disabled:opacity-40">Connect</button></div>
      </form>
    </div>
  );
}