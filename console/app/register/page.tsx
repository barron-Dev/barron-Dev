"use client";

import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";
import { supabase } from "../../lib/supabase-public";

const TYPES: [string, string][] = [
  ["company", "Company / Business"],
  ["government", "Government / Public Sector"],
  ["security_provider", "Security Provider / MSSP"],
  ["developer", "Developer"],
  ["partner", "Partner"],
  ["individual", "Individual"],
];

async function finishOrganization(accessToken: string, type: string, name: string) {
  const { data, error } = await supabase.rpc("create_customer_organization", {
    p_type: type,
    p_legal_name: name,
    p_country_code: null,
    p_domain: null,
    p_registration_number: null,
  });
  if (error) throw new Error(error.message);
  if (data === null || data === undefined) throw new Error("Organization creation returned no result.");
  sessionStorage.removeItem("cyclothone_pending_organization");
  sessionStorage.setItem("cyclothone_access_token", accessToken);
}

export default function Register() {
  const router = useRouter();
  const [type, setType] = useState("company");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
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
      const { data, error } = await supabase.auth.signUp({
        email,
        password,
        options: {
          data: {
            account_type: type,
            account_name: cleanName,
            onboarding_stage: "registered",
          },
        },
      });
      if (error) throw new Error(error.message);

      sessionStorage.setItem(
        "cyclothone_pending_organization",
        JSON.stringify({ type, name: cleanName })
      );

      if (!data.session) {
        setDone("Account created. Verify your email, then sign in to continue.");
        return;
      }

      await finishOrganization(data.session.access_token, type, cleanName);
      router.push("/customer/workspace");
    } catch (x) {
      setError(x instanceof Error ? x.message : "Registration failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="min-h-screen overflow-hidden bg-[#05070a] text-[#e8eef6]">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_70%_15%,rgba(0,217,255,.09),transparent_32%),linear-gradient(180deg,#05070a_0%,#071018_55%,#05070a_100%)]" />
      <header className="relative z-10 flex items-center justify-between border-b border-[#1a2330] px-6 py-4 md:px-10">
        <a href="/" className="font-semibold tracking-tight">Cyclothone</a>
        <a href="/login" className="text-xs text-[#8a97a8]">Already registered? Sign in</a>
      </header>
      <div className="relative z-10 mx-auto grid max-w-5xl gap-12 px-6 py-14 md:grid-cols-[1fr_420px] md:px-10 md:py-20">
        <section className="max-w-xl self-center">
          <div className="text-[10px] uppercase tracking-[.2em] text-[#00d9ff]">Enter Cyclothone</div>
          <h1 className="mt-4 text-4xl font-semibold leading-tight md:text-5xl">Start with the essentials.</h1>
          <p className="mt-5 max-w-lg text-sm leading-6 text-[#8a97a8]">Create your account in moments. Your full organization profile can be completed later when a service or verification step actually requires it.</p>
          <div className="mt-8 space-y-4 border-l border-[#1a2330] pl-5">
            <div><div className="text-[9px] uppercase tracking-[.16em] text-[#00ff9d]">01 · Identity</div><p className="mt-1 text-xs text-[#8a97a8]">What kind of account is this?</p></div>
            <div><div className="text-[9px] uppercase tracking-[.16em] text-[#00d9ff]">02 · Entity</div><p className="mt-1 text-xs text-[#8a97a8]">Who or what does it represent?</p></div>
            <div><div className="text-[9px] uppercase tracking-[.16em] text-[#8a97a8]">03 · Contact</div><p className="mt-1 text-xs text-[#8a97a8]">Which email anchors the account?</p></div>
          </div>
          <p className="mt-8 text-[10px] leading-5 text-[#5a6675]">Account creation does not grant access to sensitive services. Trust, admission and service-specific verification remain separate controls.</p>
        </section>
        <form onSubmit={submit} className="border border-[#1a2330] bg-[#0a0e14]/95 p-6 shadow-2xl md:p-7">
          <div className="mb-6"><div className="font-mono text-[9px] text-[#00d9ff]">ACCOUNT CREATION</div><h2 className="mt-2 text-xl font-medium">Three essentials</h2><p className="mt-1 text-xs text-[#5a6675]">Your profile can be completed later.</p></div>
          <div className="space-y-5">
            <label className="block text-xs">Account type<select value={type} onChange={e => setType(e.target.value)} className="mt-2 w-full border border-[#2a3646] bg-[#030508] p-3 text-sm">{TYPES.map(x => <option key={x[0]} value={x[0]}>{x[1]}</option>)}</select></label>
            <label className="block text-xs">Name or organization<input required value={name} onChange={e => setName(e.target.value)} placeholder="Your name or organization" className="mt-2 w-full border border-[#2a3646] bg-[#030508] p-3 text-sm" /></label>
            <label className="block text-xs">Email address<input required type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="you@example.com" className="mt-2 w-full border border-[#2a3646] bg-[#030508] p-3 text-sm" /></label>
            <div className="border-t border-[#1a2330] pt-5"><label className="block text-xs">Password<input required minLength={10} type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="At least 10 characters" className="mt-2 w-full border border-[#2a3646] bg-[#030508] p-3 text-sm" /></label><p className="mt-2 text-[10px] text-[#5a6675]">Credential setup is separate from the three identity questions.</p></div>
            {error && <div className="border border-[#ff2d55]/40 p-3 text-xs text-[#ff6b83]">{error}</div>}
            {done && <div className="border border-[#00e07a]/30 p-3 text-xs leading-5 text-[#7df0ad]">{done}</div>}
            <button disabled={busy} className="w-full border border-[#00d9ff] bg-[#00d9ff]/5 p-3 text-xs font-medium text-[#00d9ff] disabled:opacity-50">{busy ? "Creating account…" : "Create Cyclothone account"}</button>
            <p className="text-[10px] leading-4 text-[#5a6675]">Sensitive services may require additional identity, organization or service-specific verification.</p>
          </div>
        </form>
      </div>
    </main>
  );
}
