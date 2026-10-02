"use client";
import { useEffect, useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { SUPABASE_URL, supabase } from "../../../lib/supabase-public";

export default function CustomerOnboarding() {
 const router=useRouter(); const [name,setName]=useState(""); const [email,setEmail]=useState(""); const [phone,setPhone]=useState("");
 const [kind,setKind]=useState(""); const [country,setCountry]=useState(""); const [lei,setLei]=useState(""); const [busy,setBusy]=useState(false); const [result,setResult]=useState<any>(null); const [error,setError]=useState<string|null>(null);
 useEffect(()=>{const raw=sessionStorage.getItem("cyclothone_pending_profile");if(raw){try{const p=JSON.parse(raw);setName(p.account_name||"");setEmail(p.email||"");setPhone(p.phone_number||"")}catch{}}},[]);
 async function submit(e:FormEvent){e.preventDefault();setBusy(true);setError(null);try{
  const {data:{session}}=await supabase.auth.getSession(); if(!session) throw new Error("Authentication required. Please sign in again.");
  const response=await fetch(SUPABASE_URL+"/functions/v1/giril-onboard",{method:"POST",headers:{Authorization:"Bearer "+session.access_token,"Content-Type":"application/json"},body:JSON.stringify({name,email,phone,subject_kind:kind||null,country:country||null,lei:lei.trim()||null})});
  const payload=await response.json(); if(!response.ok) throw new Error(payload.error||"Unable to complete onboarding");
  sessionStorage.removeItem("cyclothone_pending_profile"); setResult(payload);
 }catch(e){setError(e instanceof Error?e.message:"Unable to complete onboarding")}finally{setBusy(false)}}
 return <main className="relative min-h-screen overflow-hidden bg-[#03080d] text-[#e8eef6]">
 <div aria-hidden="true" className="pointer-events-none absolute inset-0 overflow-hidden">
  <div className="absolute -left-[25%] top-[12%] h-[36rem] w-[75rem] -rotate-12 rounded-[50%] border border-[#00d9ff]/10 bg-gradient-to-r from-[#00d9ff]/[0.035] via-[#0b3b55]/[0.08] to-transparent blur-3xl animate-[pulse_9s_ease-in-out_infinite]"/>
  <div className="absolute -right-[30%] top-[48%] h-[30rem] w-[70rem] rotate-12 rounded-[50%] border border-[#35b8d4]/10 bg-gradient-to-l from-[#0b6b87]/[0.07] to-transparent blur-3xl animate-[pulse_12s_ease-in-out_infinite]"/>
  <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_15%,rgba(0,217,255,.08),transparent_34%),linear-gradient(180deg,rgba(2,10,16,.15),rgba(2,6,10,.94))]"/>
 </div>
 <header className="relative z-10 border-b border-white/[0.07] bg-[#031019]/45 px-5 py-4 backdrop-blur-xl"><a href="/" className="font-semibold">Cyclothone</a></header>
 <div className="relative z-10 mx-auto max-w-xl px-5 py-12">
 <div className="mb-7 rounded-[1.75rem] border border-white/[0.07] bg-white/[0.025] p-5 backdrop-blur-xl"><div className="text-[10px] uppercase tracking-[.18em] text-[#00d9ff]">Cyclothone onboarding</div><h1 className="mt-2 text-3xl font-semibold">Tell us about you</h1><p className="mt-2 text-sm text-[#8a97a8]">Start with the essentials. Additional proof is requested only when needed.</p></div>
 {result?<div className="border border-[#00e07a]/40 bg-[#00e07a]/5 p-5"><div className="text-lg font-medium">Onboarding submitted</div><p className="mt-2 text-sm text-[#8a97a8]">Your information is now going through the real verification and admission process.</p>{result.verification&&<div className="mt-4 border border-[#1a2330] p-3 text-xs">Company verification: <span className="font-mono">{result.verification.status}</span></div>}<button onClick={()=>router.push("/customer/workspace")} className="mt-5 border border-[#00d9ff] px-4 py-2 text-xs text-[#00d9ff]">Continue to workspace</button></div>:
 <form onSubmit={submit} className="space-y-4 rounded-[2.25rem] border border-white/[0.10] bg-[#07131b]/75 p-6 shadow-[0_30px_100px_rgba(0,0,0,.55)] backdrop-blur-2xl md:p-8">
 <label className="block text-sm">Name or company name<input required value={name} onChange={e=>setName(e.target.value)} className="mt-2 w-full rounded-2xl border border-white/[0.09] bg-[#02080d]/80 px-4 py-3.5 text-sm outline-none transition-all placeholder:text-[#506171] focus:border-[#00d9ff]/70 focus:bg-[#04131b] focus:ring-4 focus:ring-[#00d9ff]/[0.06]"/></label>
 <label className="block text-sm">Email<input required type="email" value={email} onChange={e=>setEmail(e.target.value)} className="mt-2 w-full border border-[#2a3646] bg-[#030508] p-3"/></label>
 <label className="block text-sm">Phone<input required value={phone} onChange={e=>setPhone(e.target.value)} className="mt-2 w-full border border-[#2a3646] bg-[#030508] p-3"/></label>
 <label className="block text-sm">What are you?<select required value={kind} onChange={e=>setKind(e.target.value)} className="mt-2 w-full border border-[#2a3646] bg-[#030508] p-3"><option value="">Select</option><option value="COMPANY">Company</option><option value="INDIVIDUAL">Individual</option><option value="GOVERNMENT">Government</option><option value="SECURITY_PROVIDER">Security provider</option><option value="DEVELOPER">Developer</option><option value="PARTNER">Partner</option><option value="OTHER">Other</option></select></label>
 <label className="block text-sm">Country code <span className="text-[#5a6675]">(optional)</span><input maxLength={2} value={country} onChange={e=>setCountry(e.target.value.toUpperCase())} placeholder="AE" className="mt-2 w-full border border-[#2a3646] bg-[#030508] p-3"/></label>
 {kind==="COMPANY"&&<label className="block text-sm">LEI <span className="text-[#5a6675]">(optional)</span><input maxLength={20} value={lei} onChange={e=>setLei(e.target.value.toUpperCase())} className="mt-2 w-full border border-[#2a3646] bg-[#030508] p-3"/></label>}
 {error&&<div className="border border-[#ff2d55]/40 p-3 text-sm text-[#ff6b83]">{error}</div>}<button disabled={busy} className="w-full rounded-2xl border border-[#00d9ff]/70 bg-gradient-to-r from-[#00d9ff]/10 via-[#00d9ff]/[0.04] to-transparent px-4 py-3.5 text-sm font-medium text-[#b9f6ff] shadow-[0_12px_35px_rgba(0,217,255,.08)] transition-all hover:bg-[#00d9ff]/[0.14] disabled:opacity-40">{busy?"Verifying…":"Continue"}</button></form>}
 </div></main>;
}