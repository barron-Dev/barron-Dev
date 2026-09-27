"use client";
import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";
import { supabase, SUPABASE_PUBLIC_KEY, SUPABASE_URL } from "../../lib/supabase-public";

const TYPES=[["company","Company / Business"],["government","Government / Public Sector"],["security_provider","Security Provider / MSSP"],["developer","Developer"],["client","Client"],["partner","Partner"],["individual","Individual"]];

async function createOrganization(accessToken:string, organization:{type:string;name:string;country:string;domain:string;registration:string}) {
  const r=await fetch(SUPABASE_URL+"/rest/v1/rpc/create_customer_organization",{
    method:"POST",
    headers:{apikey:SUPABASE_PUBLIC_KEY,Authorization:"Bearer "+accessToken,"Content-Type":"application/json"},
    body:JSON.stringify({
      p_type:organization.type,
      p_legal_name:organization.name,
      p_country_code:organization.country||null,
      p_domain:organization.domain||null,
      p_registration_number:organization.registration||null
    })
  });
  if(!r.ok) throw new Error(await r.text()||"Organization creation failed");
}

export default function Register(){
  const router=useRouter();
  const [type,setType]=useState("company"),[name,setName]=useState(""),[country,setCountry]=useState(""),[domain,setDomain]=useState(""),[registration,setRegistration]=useState(""),[email,setEmail]=useState(""),[password,setPassword]=useState(""),[busy,setBusy]=useState(false),[error,setError]=useState<string|null>(null),[done,setDone]=useState<string|null>(null);

  async function submit(e:FormEvent){
    e.preventDefault();setBusy(true);setError(null);setDone(null);
    try{
      const {data,error}=await supabase.auth.signUp({email,password,data:{account_type:type}});
      if(error) throw new Error(error.message);
      if(!data.session){
        sessionStorage.setItem("cyclothone_pending_organization",JSON.stringify({type,name,country,domain,registration}));
        setDone("Account created. Check your email to verify your address, then sign in to continue.");
        return;
      }
      sessionStorage.setItem("cyclothone_access_token",data.session.access_token);
      await createOrganization(data.session.access_token,{type,name,country,domain,registration});
      router.push("/customer/workspace");
    }catch(x){setError(x instanceof Error?x.message:"Registration failed")}
    finally{setBusy(false)}
  }

  return <main className="min-h-screen bg-[#05070a] text-[#e8eef6]"><header className="border-b border-[#1a2330] px-6 py-4"><a href="/" className="font-semibold">Cyclothone</a></header><div className="mx-auto max-w-2xl px-6 py-12"><div className="mb-8"><div className="text-[10px] uppercase tracking-[.18em] text-[#00d9ff]">Secure onboarding</div><h1 className="mt-2 text-3xl font-semibold">Create your Cyclothone account</h1><p className="mt-2 text-sm text-[#8a97a8]">Account authentication and organization verification are separate trust steps.</p></div><form onSubmit={submit} className="space-y-5 border border-[#1a2330] bg-[#0a0e14] p-6"><label className="block text-sm">Register as<select value={type} onChange={e=>setType(e.target.value)} className="mt-2 w-full border border-[#2a3646] bg-[#030508] p-3">{TYPES.map(x=><option key={x[0]} value={x[0]}>{x[1]}</option>)}</select></label><label className="block text-sm">Legal / organization name<input required value={name} onChange={e=>setName(e.target.value)} className="mt-2 w-full border border-[#2a3646] bg-[#030508] p-3"/></label><div className="grid gap-4 md:grid-cols-2"><label className="block text-sm">Country code<input required minLength={2} maxLength={2} value={country} onChange={e=>setCountry(e.target.value.toUpperCase())} placeholder="AE" className="mt-2 w-full border border-[#2a3646] bg-[#030508] p-3"/></label><label className="block text-sm">Company domain<input value={domain} onChange={e=>setDomain(e.target.value.toLowerCase())} placeholder="example.com" className="mt-2 w-full border border-[#2a3646] bg-[#030508] p-3"/></label></div><label className="block text-sm">Registration number<input value={registration} onChange={e=>setRegistration(e.target.value)} className="mt-2 w-full border border-[#2a3646] bg-[#030508] p-3"/></label><hr className="border-[#1a2330]"/><label className="block text-sm">Email address<input required type="email" value={email} onChange={e=>setEmail(e.target.value)} placeholder="you@company.com" className="mt-2 w-full border border-[#2a3646] bg-[#030508] p-3"/></label><label className="block text-sm">Password<input required minLength={10} type="password" value={password} onChange={e=>setPassword(e.target.value)} className="mt-2 w-full border border-[#2a3646] bg-[#030508] p-3"/></label>{error&&<div className="border border-[#ff2d55]/40 p-3 text-sm text-[#ff6b83]">{error}</div>}{done&&<div className="border border-[#00e07a]/30 p-3 text-sm text-[#7df0ad]">{done}</div>}<button disabled={busy} className="w-full border border-[#00d9ff] p-3 text-[#00d9ff] disabled:opacity-50">{busy?"Creating account…":"Create secure account"}</button><p className="text-xs text-[#5a6675]">Protected services remain subject to organization and identity verification.</p></form></div></main>
}
