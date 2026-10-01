"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { supabase } from "../../lib/supabase-public";

export default function MobileAuth() {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;

    (async () => {
      const hash = window.location.hash.startsWith("#")
        ? window.location.hash.slice(1)
        : window.location.hash;

      const params = new URLSearchParams(hash);
      const accessToken = params.get("access_token");
      const refreshToken = params.get("refresh_token");

      if (!accessToken || !refreshToken) {
        if (active) setError("Mobile authentication session is missing.");
        return;
      }

      const { error: sessionError } = await supabase.auth.setSession({
        access_token: accessToken,
        refresh_token: refreshToken,
      });

      if (sessionError) {
        if (active) setError(sessionError.message);
        return;
      }

      window.history.replaceState({}, document.title, window.location.pathname);

      if (active) router.replace("/login?confirmed=1");
    })();

    return () => {
      active = false;
    };
  }, [router]);

  if (error) {
    return (
      <main className="flex min-h-screen items-center justify-center bg-[#021014] px-6 text-[#e8f5f3]">
        <div className="max-w-md text-center">
          <h1 className="text-lg font-medium">Authentication could not be completed</h1>
          <p className="mt-3 text-sm text-[#91a8aa]">{error}</p>
          <a href="/login" className="mt-6 inline-block rounded-full border border-white/10 px-4 py-2 text-sm">
            Return to sign in
          </a>
        </div>
      </main>
    );
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-[#021014] text-[#91a8aa]">
      Completing secure sign-in…
    </main>
  );
}
