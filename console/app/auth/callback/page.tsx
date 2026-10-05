"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { setApiToken } from "../../../lib/api";
import { supabase } from "../../../lib/supabase-public";

const INVITATION_TOKEN_KEY = "cyclothone_invitation_token";
const PENDING_PROFILE_KEY = "cyclothone_pending_profile";

export default function AuthCallback() {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const params = new URLSearchParams(window.location.search);
        const code = params.get("code");
        const tokenHash = params.get("token_hash");
        let session = null;

        if (code) {
          const { data, error: exchangeError } = await supabase.auth.exchangeCodeForSession(code);
          if (exchangeError) throw exchangeError;
          session = data.session;
        } else if (tokenHash) {
          const { data, error: verifyError } = await supabase.auth.verifyOtp({ token_hash: tokenHash, type: "email" });
          if (verifyError) throw verifyError;
          session = data.session;
        } else {
          const { data, error: sessionError } = await supabase.auth.getSession();
          if (sessionError) throw sessionError;
          session = data.session;
        }

        if (!session) throw new Error("Authentication completed, but no session was created.");

        setApiToken(session.access_token);
        if (session.refresh_token) sessionStorage.setItem("cyclothone_refresh_token", session.refresh_token);

        const invitationToken = sessionStorage.getItem(INVITATION_TOKEN_KEY);
        const developerSurface =
          window.location.hostname === "developers.cyclothone.online" ||
          params.get("surface") === "developer";

        sessionStorage.removeItem("cyclothone_auth_entry");
        sessionStorage.removeItem(PENDING_PROFILE_KEY);

        router.replace(
          invitationToken
            ? "/invitations/accept"
            : developerSurface
              ? "/developers"
              : "/customer/overview",
        );
      } catch (x) {
        if (active) setError(x instanceof Error ? x.message : "Unable to finish authentication.");
      }
    })();
    return () => { active = false; };
  }, [router]);

  if (error) {
    return (
      <main className="min-h-screen bg-[#021014] px-6 py-20 text-[#e8f5f3]">
        <div className="mx-auto max-w-xl rounded-[2rem] border border-rose-300/20 bg-rose-300/[.05] p-7">
          <div className="text-[10px] uppercase tracking-[.22em] text-rose-200">Authentication</div>
          <h1 className="mt-3 text-2xl font-semibold">We could not finish sign-in.</h1>
          <p className="mt-3 text-sm leading-6 text-[#91a8aa]">{error}</p>
          <a href="/login" className="mt-6 inline-block rounded-full bg-[#2b9b96] px-5 py-3 text-sm">Return to sign in</a>
        </div>
      </main>
    );
  }

  return (
    <main className="min-h-screen bg-[#021014] px-6 py-20 text-[#e8f5f3]">
      <div className="mx-auto max-w-xl text-center">
        <div className="text-[10px] uppercase tracking-[.22em] text-[#66c9c1]">Cyclothone</div>
        <h1 className="mt-4 text-3xl font-semibold">Finishing secure sign-in…</h1>
        <p className="mt-3 text-sm text-[#789296]">Your session is being established. You will enter Cyclothone automatically.</p>
      </div>
    </main>
  );
}