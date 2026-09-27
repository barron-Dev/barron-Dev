"use client";
import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { supabase } from "../../lib/supabase-public";

const INVITATION_TOKEN_KEY="cyclothone_invitation_token";

async function finishPendingOrganization(accessToken:string){
  const pending=sessionStorage.getItem("cyclothone_pending_organization");
  if(!pending) return;
  const o=JSON.parse(pending);
  const { data, error } = await supabase.rpc("create_customer_organization",{
    p_type:o.type,p_legal_name:o.name,p_country_code:o.country||null,p_domain:o.domain||null,p_registration_number:o.registration||null
  });
  if(error) throw new Error(error.message);
  if(data===null || data===undefined) throw new Error("Organization creation returned no result.");
  sessionStorage.removeItem("cyclothone_pending_organization");
  sessionStorage.setItem("cyclothone_access_token",accessToken);
}

export default function Login(){
 const router=useRouter();const [email,setEmail]=useState(""),[password,setPassword]=useState(""),[busy,setBusy]=useState(false),[error,setError]=useState<string|null>(null);
 useEffect(()=>{const token=new URLSearchParams(window.location.search).get("token");if(token)sessionStorage.setItem(INVITATION_TOKEN_KEY,token)},[]);
 async function submit(e:FormEvent){
  e.preventDefault();setBusy(true);setError(null);
  try{
   const {data,error}=await supabase.auth.signInWithPassword({email,password});
   if(error||!data.session) throw new Error(error?.message||"Sign-in failed");
   sessionStorage.setItem("cyclothone_access_token",data.session.access_token);
   if(data.session.refresh_token) sessionStorage.setItem("cyclothone_refresh_token",data.session.refresh_token);
   await finishPendingOrganization(data.session.access_token);
   const invitationToken=sessionStorage.getItem(INVITATION_TOKEN_KEY);
   router.push(invitationToken?"/invitations/accept":"/customer/workspace");
  }catch(x){setError(x instanceof Error?x.message:"Sign-in failed")}
  finally{setBusy(false)}
 }
 return <main className="min-h-screen bg-[#05070a] text-[#e8eef6]"><header className="border-b border-[#1a2330] px-6 py-4"><a href="/" className="font-semibold">Cyclothone</a></header><div className="mx-auto max-w-md px-6 py-16"><div className="mb-8"><div className="text-[10px] uppercase tracking-[.18em] text-[#00d9ff]">Secure authentication</div><h1 className="mt-2 text-3xl font-semibold">Sign in</h1><p className="mt-2 text-sm text-[#8a97a8]">Use the account you registered with. Higher-risk operations may require additional verification.</p></div><form onSubmit={submit} className="space-y-5 border border-[#1a2330] bg-[#0a0e14] p-6"><label className="block text-sm">Email<input required type="email" value={email} onChange={e=>setEmail(e.target.value)} className="mt-2 w-full border border-[#2a3646] bg-[#030508] p-3"/></label><label className="block text-sm">Password<input required type="password" value={password} onChange={e=>setPassword(e.target.value)} className="mt-2 w-full border border-[#2a3646] bg-[#030508] p-3"/></label>{error&&<div className="border border-[#ff2d55]/40 p-3 text-sm text-[#ff6b83]">{error}</div>}<button disabled={busy} className="w-full border border-[#00d9ff] p-3 text-[#00d9ff] disabled:opacity-50">{busy?"Signing in…":"Sign in"}</button><a href="/register" className="block text-center text-sm text-[#8a97a8]">Create a new account</a></form></div></main>;
}
