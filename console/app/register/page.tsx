"use client";

import { FormEvent, useState } from "react";
import { supabase } from "../../lib/supabase-public";

type Entry = "google" | "github" | "email" | "form";

function cleanPhone(value: string) {
  return value.replace(/[()\s-]/g, "");
}

export default function Register() {
  const [entry, setEntry] = useState<Entry | null>(null);
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [phone, setPhone] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  function beginEntry(next: Entry) {
    setError(null);
    setDone(null);
    setEntry(next);
    if (next === "google" || next === "github") void oauth(next);
  }

  async function oauth(provider: "google" | "github") {
    setBusy(true);
    try {
      sessionStorage.setItem("cyclothone_auth_entry", "registration");
      const redirectTo = `${window.location.origin}/login?confirmed=1`;
      const { error } = await supabase.auth.signInWithOAuth({
        provider,
        options: {
          redirectTo,
          queryParams: provider === "google" ? { access_type: "offline", prompt: "select_account" } : undefined,
        },
      });
      if (error) throw new Error(error.message);
    } catch (x) {
      setError(x instanceof Error ? x.message : "Unable to continue");
      setBusy(false);
    }
  }

  async function sendEmail(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setDone(null);
    try {
      const cleanEmail = email.trim().toLowerCase();
      if (!cleanEmail) throw new Error("Enter your email address.");
      const redirectTo = `${window.location.origin}/login?confirmed=1`;
      sessionStorage.setItem(
        "cyclothone_pending_profile",
        JSON.stringify({ name: "", email: cleanEmail, phone: "" })
      );
      sessionStorage.setItem("cyclothone_auth_entry", "registration");
      const { error } = await supabase.auth.signInWithOtp({
        email: cleanEmail,
        options: { emailRedirectTo: redirectTo, shouldCreateUser: true },
      });
      if (error) throw new Error(error.message);
      setDone("Verification link sent. Open it to continue.");
    } catch (x) {
      setError(x instanceof Error ? x.message : "Unable to send verification link");
    } finally {
      setBusy(false);
    }
  }

  async function submitForm(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setDone(null);
    try {
      const cleanName = name.trim();
      const cleanEmail = email.trim().toLowerCase();
      const cleanPhone = cleanPhone(phone);
      if (!cleanName) throw new Error("Enter your name or company name.");
      if (!cleanEmail) throw new Error("Enter your email address.");
      if (!cleanPhone) throw new Error("Enter your phone number.");

      const redirectTo = `${window.location.origin}/login?confirmed=1`;
      sessionStorage.setItem(
        "cyclothone_pending_profile",
        JSON.stringify({ name: cleanName, email: cleanEmail, phone: cleanPhone })
      );
      sessionStorage.setItem("cyclothone_auth_entry", "registration");

      const { error } = await supabase.auth.signInWithOtp({
        email: cleanEmail,
        options: {
          emailRedirectTo: redirectTo,
          shouldCreateUser: true,
          data: { account_name: cleanName, phone_number: cleanPhone, onboarding_stage: "registered" },
        },
      });
      if (error) throw new Error(error.message);
      setDone("Verification link sent. Open it to continue.");
    } catch (x) {
      setError(x instanceof Error ? x.message : "Registration failed");
    } finally {
      setBusy(false);
    }
  }

  const inputClass = "mt-2 w-full rounded-[1.15rem] border border-white/10 bg-[#06131a]/75 px-4 py-3.5 text-sm outline-none transition placeholder:text-[#65808c] focus:border-[#35c8c1]/60 focus:bg-[#071b23] focus:ring-4 focus:ring-[#35c8c1]/10";

  return (
    <main className="relative min-h-screen overflow-hidden bg-[#021014] text-[#e8f5f3]">
      <div aria-hidden="true" className="pointer-events-none absolute inset-0 overflow-hidden">
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_50%_0%,rgba(15,94,100,.42),transparent_45%),linear-gradient(180deg,#031a20_0%,#021014_52%,#01090c_100%)]" />
        <svg className="absolute -left-[12%] top-[8%] h-[75%] w-[125%] opacity-70" viewBox="0 0 1400 700" preserveAspectRatio="none">
          <defs>
            <linearGradient id="waveA" x1="0" x2="1">
              <stop offset="0" stopColor="#0a4d55" stopOpacity=".18" />
              <stop offset=".5" stopColor="#1b8b89" stopOpacity=".28" />
              <stop offset="1" stopColor="#06353f" stopOpacity=".08" />
            </linearGradient>
          </defs>
          <path d="M-80 420 C180 250 360 610 650 405 C900 225 1080 510 1480 300 L1480 760 L-80 760 Z" fill="url(#waveA)">
            <animateTransform attributeName="transform" type="translate" values="0 0; -70 14; 0 0" dur="18s" repeatCount="indefinite" />
          </path>
          <path d="M-100 500 C190 350 410 690 700 470 C970 265 1170 560 1510 390" fill="none" stroke="#55c8c0" strokeOpacity=".11" strokeWidth="2">
            <animateTransform attributeName="transform" type="translate" values="0 0; 90 -8; 0 0" dur="24s" repeatCount="indefinite" />
          </path>
        </svg>
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_30%_70%,rgba(20,135,133,.16),transparent_25%),radial-gradient(circle_at_75%_35%,rgba(16,80,95,.18),transparent_30%)]" />
      </div>

      <header className="relative z-10 flex items-center justify-between px-6 py-6 md:px-10">
        <a href="/" className="font-semibold tracking-[-.02em]">Cyclothone</a>
        <a href="/login" className="rounded-full border border-white/10 bg-white/[.035] px-4 py-2 text-xs text-[#a6b9bb] backdrop-blur-xl hover:bg-white/[.06]">Sign in</a>
      </header>

      <div className="relative z-10 mx-auto flex min-h-[calc(100vh-96px)] max-w-5xl items-center justify-center px-6 pb-16">
        <section className="w-full max-w-3xl text-center">
          <div className="text-[10px] uppercase tracking-[.28em] text-[#66c9c1]">Enter Cyclothone</div>
          <h1 className="mt-4 text-4xl font-semibold tracking-[-.04em] md:text-6xl">Your account. Your way.</h1>
          <p className="mx-auto mt-5 max-w-xl text-sm leading-7 text-[#91a8aa]">Choose an entry point. Cyclothone keeps the entrance light and does the deeper identity work behind it.</p>

          <div className="mx-auto mt-10 grid max-w-2xl grid-cols-2 gap-3 md:grid-cols-4">
            {[
              ["google", "Google", "Continue instantly"],
              ["github", "GitHub", "Developer access"],
              ["email", "Email", "Magic link"],
              ["form", "Fill form", "Name · email · phone"],
            ].map(([value, title, sub]) => (
              <button
                key={value}
                type="button"
                disabled={busy}
                onClick={() => beginEntry(value as Entry)}
                className="group rounded-[1.5rem] border border-white/10 bg-[#06181e]/55 px-4 py-5 text-left shadow-[0_18px_60px_rgba(0,0,0,.28)] backdrop-blur-xl transition-all hover:-translate-y-1 hover:border-[#45bdb6]/35 hover:bg-[#08232a]/75 disabled:opacity-50"
              >
                <span className="block text-sm font-medium text-[#e5f2f0]">{title}</span>
                <span className="mt-1 block text-[10px] leading-4 text-[#759093]">{sub}</span>
              </button>
            ))}
          </div>

          {entry === "email" && (
            <form onSubmit={sendEmail} className="mx-auto mt-5 max-w-2xl rounded-[2rem] border border-white/10 bg-[#06171d]/72 p-5 text-left shadow-[0_30px_100px_rgba(0,0,0,.4)] backdrop-blur-2xl">
              <label className="block text-xs text-[#b6c7c8]">Email address<input required autoFocus type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="you@company.com" className={inputClass} /></label>
              <button disabled={busy} className="mt-4 w-full rounded-[1.15rem] bg-[#2b9b96] px-4 py-3.5 text-sm font-medium text-white shadow-[0_14px_35px_rgba(43,155,150,.22)] transition hover:bg-[#35aaa4] disabled:opacity-50">{busy ? "Sending…" : "Send secure link"}</button>
            </form>
          )}

          {entry === "form" && (
            <form onSubmit={submitForm} className="mx-auto mt-5 max-w-2xl rounded-[2rem] border border-white/10 bg-[#06171d]/72 p-6 text-left shadow-[0_30px_100px_rgba(0,0,0,.4)] backdrop-blur-2xl md:p-7">
              <div className="mb-5"><div className="text-[10px] uppercase tracking-[.2em] text-[#66c9c1]">Light registration</div><p className="mt-1 text-xs text-[#789193]">Only three essentials. Verification comes after the door.</p></div>
              <div className="grid gap-4 md:grid-cols-2">
                <label className="block text-xs text-[#b6c7c8] md:col-span-2">Name or company name<input required value={name} onChange={e => setName(e.target.value)} placeholder="Your name or company name" className={inputClass} /></label>
                <label className="block text-xs text-[#b6c7c8]">Email<input required type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="you@company.com" className={inputClass} /></label>
                <label className="block text-xs text-[#b6c7c8]">Phone<input required type="tel" value={phone} onChange={e => setPhone(e.target.value)} placeholder="+971 50 123 4567" className={inputClass} /></label>
              </div>
              <button disabled={busy} className="mt-5 w-full rounded-[1.15rem] bg-[#2b9b96] px-4 py-3.5 text-sm font-medium text-white shadow-[0_14px_35px_rgba(43,155,150,.22)] transition hover:bg-[#35aaa4] disabled:opacity-50">{busy ? "Sending…" : "Continue"}</button>
            </form>
          )}

          {error && <div className="mx-auto mt-4 max-w-2xl rounded-2xl border border-rose-400/25 bg-rose-400/[.06] p-4 text-left text-xs text-rose-200">{error}</div>}
          {done && <div className="mx-auto mt-4 max-w-2xl rounded-2xl border border-emerald-300/20 bg-emerald-300/[.05] p-4 text-left text-xs text-emerald-100">{done}</div>}

          <p className="mx-auto mt-8 max-w-xl text-[10px] leading-5 text-[#617779]">After authentication, Cyclothone continues into intelligent onboarding and asks only for the evidence relevant to your identity.</p>
        </section>
      </div>
    </main>
  );
}
