"use client";

import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { createCustomerOrganization, getCustomerOrganizations, type CustomerOrganization } from "../../../lib/api";

const TYPES = [
  ["company","Company"],["individual","Individual"],["government","Government"],["security_provider","Security provider"],["developer","Developer"],["partner","Partner"],["client","Client"],
] as const;

export default function CustomerProfile() {
  const router = useRouter();
  const [orgs,setOrgs]=useState<CustomerOrganization[]>([]);
  const [type,setType]=useState<(typeof TYPES)[number][0]>("company");
  const [name,setName]=useState("");
  const [country,setCountry]=useState("");
  const [domain,setDomain]=useState("");
  const [registration,setRegistration]=useState("");
  const [busy,setBusy]=useState(false);
  const [loading,setLoading]=useState(true);
  const [error,setError]=useState("");

  async function load(){
    setLoading(true); setError("");
    try { const r=await getCustomerOrganizations(); setOrgs(r.organizations); }
    catch(e){ setError(e instanceof Error ? e.message : "Unable to load your profile"); }
    finally{ setLoading(false); }
  }
  useEffect(()=>{ void load(); },[]);

  async function submit(e:FormEvent){
    e.preventDefault(); setBusy(true); setError("");
    try{
      const org=await createCustomerOrganization({
        organization_type:type, legal_name:name.trim(), country_code:country.trim().toUpperCase()||null,
        website_domain:domain.trim()||null, registration_number:registration.trim()||null,
      });
      setOrgs(prev=>[...prev,org]);
      router.push("/customer/overview");
    }catch(e){ setError(e instanceof Error ? e.message : "Unable to create organization"); }
    finally{ setBusy(false); }
  }

  return <main className="cyclo-water min-h-screen overflow-hidden text-[#e8eef6]">
    <header className="relative z-10 flex items-center justify-between border-b border-white/10 bg-[#02090e]/70 px-5 py-4 backdrop-blur-2xl">
      <div><a href="/customer/overview" className="cyclo-mark font-semibold tracking-tight">◌ CYCLOTHONE</a><span className="ml-3 text-[10px] uppercase tracking-[.16em] text-[#8a97a8]">Profile</span></div>
      <a href="/customer/services" className="cyclo-pill px-3 py-2 text-[10px] text-[#c2f35a]">Services</a>
    </header>
    <div className="relative z-10 mx-auto max-w-4xl px-5 py-10 md:py-14">
      <div className="text-[10px] uppercase tracking-[.18em] text-[#5a6675]">Your account</div>
      <h1 className="mt-2 text-3xl font-semibold">Profile & organizations</h1>
      <p className="mt-3 text-sm leading-6 text-[#8a97a8]">Your authentication is already complete. Create an organization here when a protected Cyclothone service needs an organizational security boundary. You will not need to sign in again.</p>
      {error&&<div className="mt-6 border border-[#ff2d55]/40 bg-[#ff2d55]/5 p-4 text-xs text-[#ff6b83]">{error}</div>}
      {loading?<div className="mt-8 text-xs text-[#5a6675]">Loading profile…</div>:<>
        {orgs.length>0&&<section className="cyclo-stage mt-8 p-6"><h2 className="font-medium">Your organizations</h2><div className="mt-4 space-y-2">{orgs.map(o=><div key={o.id} className="flex items-center justify-between border-b border-[#1a2330] py-3"><div><div className="text-sm">{o.legal_name}</div><div className="mt-1 text-[10px] text-[#5a6675]">{o.organization_type} · {o.country_code||"Country not set"}</div></div><span className="rounded border border-[#2a3646] px-2 py-1 text-[9px]">{o.admission_status}</span></div>)}</div></section>}
        <form onSubmit={submit} className="cyclo-stage mt-8 p-6">
          <h2 className="font-medium">Create organization</h2>
          <div className="mt-4 grid gap-4 md:grid-cols-2">
            <label className="text-xs">Organization type<select value={type} onChange={e=>setType(e.target.value as typeof type)} className="mt-2 w-full border border-[#2a3646] bg-[#05070a] p-3">{TYPES.map(([v,l])=><option key={v} value={v}>{l}</option>)}</select></label>
            <label className="text-xs">Legal / organization name<input required value={name} onChange={e=>setName(e.target.value)} className="mt-2 w-full border border-[#2a3646] bg-[#05070a] p-3" placeholder="Your company or organization"/></label>
            <label className="text-xs">Country code<input maxLength={2} value={country} onChange={e=>setCountry(e.target.value.toUpperCase())} className="mt-2 w-full border border-[#2a3646] bg-[#05070a] p-3" placeholder="AE"/></label>
            <label className="text-xs">Website domain <span className="text-[#5a6675]">(optional)</span><input value={domain} onChange={e=>setDomain(e.target.value)} className="mt-2 w-full border border-[#2a3646] bg-[#05070a] p-3" placeholder="company.com"/></label>
            <label className="text-xs md:col-span-2">Registration number <span className="text-[#5a6675]">(optional)</span><input value={registration} onChange={e=>setRegistration(e.target.value)} className="mt-2 w-full border border-[#2a3646] bg-[#05070a] p-3"/></label>
          </div>
          <button disabled={busy} className="mt-5 w-full rounded-full border border-[#c2f35a]/50 bg-[#c2f35a]/10 px-4 py-3 text-sm text-[#ddff9a] transition hover:bg-[#c2f35a]/15 disabled:opacity-40">{busy?"Creating organization…":"Create organization"}</button>
        </form>
      </>}
    </div>
  </main>;
}
