"use client";

import { FormEvent, useState } from "react";
import { supabase } from "../../lib/supabase-public";

type Method = "email" | "phone" | "google";

function cleanPhone(value: string) {
  return value.replace(/[()\s-]/g, "");
}

export default function Register() {
  const [method, setMethod] = useState<Method>("email");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [phone, setPhone] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setDone(null);

    try {
      const cleanName = name.trim();
      const cleanEmail = email.trim().toLowerCase();
      const cleanPhone = cleanPhoneValue(phone);

      if (!cleanName) throw new Error("Enter your name or company name.");
      if (!cleanEmail) throw new Error("Enter your email address.");
      if (!cleanPhone) throw new Error("Enter your phone number.");

      const redirectTo = `${window.location.origin}/login?confirmed=1`;
      sessionStorage.setItem(
        "cyclothone_pending_profile",
        JSON.stringify({ name: cleanName, email: cleanEmail, phone: cleanPhone })
      );

      if (method === "google") {
        const { error } = await supabase.auth.signInWithOAuth({
          provider: "google",
          options: {
            redirectTo,
            queryParams: { access_type: "offline", prompt: "select_account" },
          },
        });
        if (error) throw new Error(error.message);
        return;
      }

      if (method === "phone") {
        const { error } = await supabase.auth.signInWithOtp({
          phone: cleanPhone,
          options: {
            shouldCreateUser: true,
            data: {
              account_name: cleanName,
              phone_number: cleanPhone,
              onboarding_stage: "registered",
            },
          },
        });
        if (error) throw new Error(error.message);
        setDone("We sent a verification code to your phone. Verify it to continue.");
        return;
      }

      const { error } = await supabase.auth.signInWithOtp({
        email: cleanEmail,
        options: {
          emailRedirectTo: redirectTo,
          shouldCreateUser: true,
          data: {
            account_name: cleanName,
            phone_number: cleanPhone,
            onboarding_stage: "registered",
          },
        },
      });
      if (error) throw new Error(error.message);
      setDone("Check your email. Use the Cyclothone verification link to continue.");
    } catch (x) {
      setError(x instanceof Error ? x.message : "Registration failed");
    } finally {
      setBusy(false);
    }
  }

  function cleanPhoneValue(value: string) {
    return cleanPhone(value);
  }

  return (
    <main className="min-h-screen bg-[#05070a] text-[#e8eef6]">
      <header className="flex items-center justify-between border-b border-[#1a2330] px-6 py-4 md:px-10">
        <a href="/" className="font-semibold tracking-tight">Cyclothone</a>
        <a href="/login" className="text-xs text-[#8a97a8]">Already have an account? Sign in</a>
      </header>

      <div className="mx-auto max-w-4xl px-6 py-12 md:py-20">
        <section className="mx-auto max-w-2xl text-center">
          <div className="text-[10px] uppercase tracking-[.22em] text-[#00d9ff]">Enter Cyclothone</div>
          <h1 className="mt-4 text-4xl font-semibold tracking-tight md:text-5xl">Start in seconds.</h1>
          <p className="mx-auto mt-4 max-w-xl text-sm leading-6 text-[#8a97a8]">
            Give us only what we need to create your account. We verify and build your real profile during onboarding — when the information actually matters.
          </p>
        </section>

        <form onSubmit={submit} className="mx-auto mt-10 max-w-xl border border-[#1a2330] bg-[#0a0e14] p-6 shadow-2xl md:p-8">
          <div className="mb-7">
            <div className="font-mono text-[9px] text-[#00d9ff]">ACCOUNT CREATION</div>
            <h2 className="mt-2 text-xl font-medium">Three things. That's it.</h2>
            <p className="mt-1 text-xs text-[#5a6675]">No company registration forms at the door.</p>
          </div>

          <div className="space-y-5">
            <label className="block text-xs">
              Name or company name
              <input
                required
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="Your name or company name"
                autoComplete="name organization"
                className="mt-2 w-full border border-[#2a3646] bg-[#030508] p-3 text-sm outline-none focus:border-[#00d9ff]"
              />
            </label>

            <label className="block text-xs">
              Email address
              <input
                required
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                placeholder="you@company.com"
                autoComplete="email"
                className="mt-2 w-full border border-[#2a3646] bg-[#030508] p-3 text-sm outline-none focus:border-[#00d9ff]"
              />
            </label>

            <label className="block text-xs">
              Phone number
              <input
                required
                type="tel"
                value={phone}
                onChange={e => setPhone(e.target.value)}
                placeholder="+971 50 123 4567"
                autoComplete="tel"
                className="mt-2 w-full border border-[#2a3646] bg-[#030508] p-3 text-sm outline-none focus:border-[#00d9ff]"
              />
              <span className="mt-1 block text-[10px] text-[#5a6675]">Use international format, e.g. +971…</span>
            </label>

            <div className="pt-2">
              <div className="mb-2 text-[10px] uppercase tracking-[.16em] text-[#5a6675]">Continue securely with</div>
              <div className="grid grid-cols-3 gap-2">
                {(["email", "phone", "google"] as Method[]).map(item => (
                  <button
                    key={item}
                    type="button"
                    onClick={() => setMethod(item)}
                    className={`border p-3 text-xs transition ${method === item ? "border-[#00d9ff] text-[#00d9ff] bg-[#00d9ff]/5" : "border-[#2a3646] text-[#8a97a8]"}`}
                  >
                    {item === "email" ? "Email" : item === "phone" ? "Phone" : "Google"}
                  </button>
                ))}
              </div>
            </div>

            {error && <div className="border border-[#ff2d55]/40 p-3 text-xs leading-5 text-[#ff6b83]">{error}</div>}
            {done && <div className="border border-[#00e07a]/30 p-3 text-xs leading-5 text-[#7df0ad]">{done}</div>}

            <button
              disabled={busy}
              className="w-full border border-[#00d9ff] bg-[#00d9ff]/5 p-3 text-xs font-medium text-[#00d9ff] disabled:opacity-50"
            >
              {busy ? "Securing your account…" : method === "google" ? "Continue with Google" : method === "phone" ? "Send phone code" : "Send secure email link"}
            </button>

            <p className="text-center text-[10px] leading-5 text-[#5a6675]">
              Account creation is intentionally lightweight. During onboarding, Cyclothone will determine whether you are an individual, company, government entity, security provider or partner and request only the evidence required for that identity.
            </p>
          </div>
        </form>
      </div>
    </main>
  );
}
