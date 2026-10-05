"use client";

import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { supabase } from "../../lib/supabase-public";

const INVITATION_TOKEN_KEY = "cyclothone_invitation_token";
const PENDING_PROFILE_KEY = "cyclothone_pending_profile";

export default function Login() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [mode, setMode] = useState<"email" | "password" | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const token = params.get("token");
    if (token) sessionStorage.setItem(INVITATION_TOKEN_KEY, token);
    if (params.get("confirmed") !== "1") return;

    let active = true;
    (async () => {
      const { data, error } = await supabase.auth.getSession();
      if (!active) return;
      if (error) { setError(error.message); return; }
      if (!data.session) { setError("Verification completed, but no session was returned. Please use the verification link again."); return; }
      sessionStorage.setItem("cyclothone_access_token", data.session.access_token);
      if (data.session.refresh_token) sessionStorage.setItem("cyclothone_refresh_token", data.session.refresh_token);
      try {
        const invitationToken = sessionStorage.getItem(INVITATION_TOKEN_KEY);
        const authEntry = sessionStorage.getItem("cyclothone_auth_entry");
        const developerSurface = window.location.hostname === "developers.cyclothone.online" || authEntry === "developer";
        router.replace(
          invitationToken
            ? "/invitations/accept"
            : developerSurface
                ? "/developers"
                : "/customer/overview",
        );
        sessionStorage.removeItem("cyclothone_auth_entry");
        sessionStorage.removeItem(PENDING_PROFILE_KEY);
      } catch (x) {
        setError(x instanceof Error ? x.message : "Unable to finish authentication");
      }
    })();
    return () => { active = false; };
  }, [router]);

  function authCallbackUrl() {
    const host = window.location.hostname;
    const developer = host === "developers.cyclothone.online" || sessionStorage.getItem("cyclothone_auth_entry") === "developer";
    const targetHost = developer ? "developers.cyclothone.online" : "customers.cyclothone.online";
    return "https://" + targetHost + "/auth/callback?surface=" + (developer ? "developer" : "customer");
  }

  async function oauth(provider: "google" | "github") {
    setBusy(true); setError(null);
    try {
      const { error } = await supabase.auth.signInWithOAuth({
        provider,
        options: {
          redirectTo: authCallbackUrl(),
          queryParams: provider === "google" ? { access_type: "offline", prompt: "select_account" } : undefined,
        },
      });
      if (error) throw new Error(error.message);
    } catch (x) {
      setError(x instanceof Error ? x.message : "Unable to continue");
      setBusy(false);
    }
  }

  async function sendEmailLink(e: FormEvent) {
    e.preventDefault(); setBusy(true); setError(null); setDone(null);
    try {
      const cleanEmail = email.trim().toLowerCase();
      if (!cleanEmail) throw new Error("Enter your email address.");
      sessionStorage.removeItem(PENDING_PROFILE_KEY);
      const { error } = await supabase.auth.signInWithOtp({
        email: cleanEmail,
        options: { emailRedirectTo: authCallbackUrl(), shouldCreateUser: false },
      });
      if (error) throw new Error(error.message);
      setDone("Sign-in link sent. Open it to enter Cyclothone.");
    } catch (x) {
      setError(x instanceof Error ? x.message : "Unable to send sign-in link");
    } finally { setBusy(false); }
  }

  async function submitPassword(e: FormEvent) {
    e.preventDefault(); setBusy(true); setError(null);
    try {
      const { data, error } = await supabase.auth.signInWithPassword({ email, password });
      if (error || !data.session) throw new Error(error?.message || "Sign-in failed");
      sessionStorage.setItem("cyclothone_access_token", data.session.access_token);
      if (data.session.refresh_token) sessionStorage.setItem("cyclothone_refresh_token", data.session.refresh_token);
      const invitationToken = sessionStorage.getItem(INVITATION_TOKEN_KEY);
      const developerSurface = window.location.hostname === "developers.cyclothone.online" || sessionStorage.getItem("cyclothone_auth_entry") === "developer";
      sessionStorage.removeItem("cyclothone_auth_entry");
      sessionStorage.removeItem(PENDING_PROFILE_KEY);
      router.push(invitationToken ? "/invitations/accept" : developerSurface ? "/developers" : "/customer/overview");
    } catch (x) {
      setError(x instanceof Error ? x.message : "Sign-in failed");
    } finally { setBusy(false); }
  }

  const inputClass = "mt-2 w-full rounded-[1.15rem] border border-white/10 bg-[#06131a]/75 px-4 py-3.5 text-sm outline-none transition placeholder:text-[#65808c] focus:border-[#35c8c1]/60 focus:bg-[#071b23] focus:ring-4 focus:ring-[#35c8c1]/10";

  return (
    <main className="relative min-h-screen overflow-hidden bg-[#021014] text-[#e8f5f3]">
      <div aria-hidden="true" className="pointer-events-none absolute inset-0 overflow-hidden">
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_50%_0%,rgba(15,94,100,.42),transparent_45%),linear-gradient(180deg,#031a20_0%,#021014_52%,#01090c_100%)]" />
        <svg className="absolute -left-[12%] top-[8%] h-[75%] w-[125%] opacity-70" viewBox="0 0 1400 700" preserveAspectRatio="none">
          <path d="M-80 420 C180 250 360 610 650 405 C900 225 1080 510 1480 300 L1480 760 L-80 760 Z" fill="#0b555b" fillOpacity=".20">
            <animateTransform attributeName="transform" type="translate" values="0 0; -70 14; 0 0" dur="18s" repeatCount="indefinite" />
          </path>
          <path d="M-100 500 C190 350 410 690 700 470 C970 265 1170 560 1510 390" fill="none" stroke="#65c9c1" strokeOpacity=".12" strokeWidth="2">
            <animateTransform attributeName="transform" type="translate" values="0 0; 90 -8; 0 0" dur="24s" repeatCount="indefinite" />
          </path>
        </svg>
      </div>

      <header className="relative z-10 flex items-center justify-between px-6 py-6 md:px-10">
        <a href="/" className="font-semibold tracking-[-.02em]">Cyclothone</a>
        <a href="/register" className="rounded-full border border-white/10 bg-white/[.035] px-4 py-2 text-xs text-[#a6b9bb] backdrop-blur-xl">Create account</a>
      </header>

      <div className="relative z-10 mx-auto flex min-h-[calc(100vh-96px)] max-w-5xl items-center justify-center px-6 pb-16">
        <section className="w-full max-w-3xl text-center">
          <div className="text-[10px] uppercase tracking-[.28em] text-[#66c9c1]">Welcome back</div>
          <h1 className="mt-4 text-4xl font-semibold tracking-[-.04em] md:text-6xl">Return to the current.</h1>
          <p className="mx-auto mt-5 max-w-xl text-sm leading-7 text-[#91a8aa]">Choose the way you want to enter. Higher-risk operations may still request additional verification inside Cyclothone.</p>

          <div className="mx-auto mt-10 grid max-w-2xl grid-cols-2 gap-3 md:grid-cols-4">
            {[
              ["google", "Google", "Continue instantly"],
              ["github", "GitHub", "Developer access"],
              ["email", "Email", "Magic link"],
              ["password", "Password", "Use password"],
            ].map(([value, title, sub]) => (
              <button key={value} type="button" disabled={busy} onClick={() => {
                setError(null); setDone(null);
                if (value === "google" || value === "github") void oauth(value);
                else setMode(value as "email" | "password");
              }} className="rounded-[1.5rem] border border-white/10 bg-[#06181e]/55 px-4 py-5 text-left shadow-[0_18px_60px_rgba(0,0,0,.28)] backdrop-blur-xl transition-all hover:-translate-y-1 hover:border-[#45bdb6]/35 hover:bg-[#08232a]/75 disabled:opacity-50">
                <span className="block text-sm font-medium text-[#e5f2f0]">{title}</span>
                <span className="mt-1 block text-[10px] leading-4 text-[#759093]">{sub}</span>
              </button>
            ))}
          </div>

          {mode === "email" && (
            <form onSubmit={sendEmailLink} className="mx-auto mt-5 max-w-2xl rounded-[2rem] border border-white/10 bg-[#06171d]/72 p-5 text-left shadow-[0_30px_100px_rgba(0,0,0,.4)] backdrop-blur-2xl">
              <label className="block text-xs text-[#b6c7c8]">Email address<input required autoFocus type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="you@company.com" className={inputClass} /></label>
              <button disabled={busy} className="mt-4 w-full rounded-[1.15rem] bg-[#2b9b96] px-4 py-3.5 text-sm font-medium text-white shadow-[0_14px_35px_rgba(43,155,150,.22)]">{busy ? "Sending…" : "Send sign-in link"}</button>
            </form>
          )}

          {mode === "password" && (
            <form onSubmit={submitPassword} className="mx-auto mt-5 max-w-2xl rounded-[2rem] border border-white/10 bg-[#06171d]/72 p-5 text-left shadow-[0_30px_100px_rgba(0,0,0,.4)] backdrop-blur-2xl">
              <div className="grid gap-4 md:grid-cols-2">
                <label className="block text-xs text-[#b6c7c8]">Email<input required type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="you@company.com" className={inputClass} /></label>
                <label className="block text-xs text-[#b6c7c8]">Password<input required type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="Your password" className={inputClass} /></label>
              </div>
              <button disabled={busy} className="mt-4 w-full rounded-[1.15rem] bg-[#2b9b96] px-4 py-3.5 text-sm font-medium text-white">{busy ? "Signing in…" : "Sign in"}</button>
            </form>
          )}

          {error && <div className="mx-auto mt-4 max-w-2xl rounded-2xl border border-rose-400/25 bg-rose-400/[.06] p-4 text-left text-xs text-rose-200">{error}</div>}
          {done && <div className="mx-auto mt-4 max-w-2xl rounded-2xl border border-emerald-300/20 bg-emerald-300/[.05] p-4 text-left text-xs text-emerald-100">{done}</div>}

          <p className="mx-auto mt-8 max-w-xl text-[10px] leading-5 text-[#617779]">Cyclothone keeps authentication simple at the surface. Trust and verification continue behind the entrance when required.</p>
        </section>
      </div>
    </main>
  );
}
