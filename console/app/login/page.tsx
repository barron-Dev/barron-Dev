"use client";
import {FormEvent,useEffect,useState} from "react";
import {useRouter} from "next/navigation";
const API=(process.env.NEXT_PUBLIC_SUPABASE_URL??"").replace(/\/$/,""),KEY=process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY??"";
const INVITATION_TOKEN_KEY="cyclothone_invitation_token";
export default function Login(){
 const router=useRouter();const [email,setEmail]=useState(""),[password,setPassword]=useState(""),[busy,setBusy]=useState(false),[error,setError]=useState<string|null>(null);
 useEffect(()=>{const token=new URLSearchParams(window.location.search).get("token");if(token)sessionStorage.setItem(INVITATION_TOKEN_KEY,token)},[]);
 async function submit(e:FormEvent){e.preventDefault();setBusy(true);setError(null);try{
  if(!API||!KEY)throw new Error("Supabase authentication is not configured.");
  const r=await fetch(API+"/auth/v1/token?grant_type=password",{method:"POST",headers:{"apikey":KEY,"Content-Type":"application/json"},body:JSON.stringify({email,password})});
  const raw=await r.text();let b:any={};try{b=JSON.parse(raw)}catch{}
  if(!r.ok)throw new Error(b.error_description||b.msg||b.message||"Sign-in failed");
  sessionStorage.setItem("cyclothone_access_token",b.access_token);if(b.refresh_token)sessionStorage.setItem("cyclothone_refresh_token",b.refresh_token);
  const invitationToken=sessionStorage.getItem(INVITATION_TOKEN_KEY);router.push(invitationToken?"/invitations/accept":"/");
 }catch(x){setError(x instanceof Error?x.message:"Sign-in failed")}finally{setBusy(false)}}
 return <main className="min-h-screen bg-[#05070a] text-[#e8eef6]"><header className="border-b border-[#1a2330] px-6 py-4"><a href="/" className="font-semibold">Cyclothone</a></header><div className="mx-auto max-w-md px-6 py-16"><div className="mb-8"><div className="text-[10px] uppercase tracking-[.18em] text-[#00d9ff]">Secure authentication</div><h1 className="mt-2 text-3xl font-semibold">Sign in</h1><p className="mt-2 text-sm text-[#8a97a8]">Use the account you registered with. Higher-risk operations may require additional verification.</p></div><form onSubmit={submit} className="space-y-5 border border-[#1a2330] bg-[#0a0e14] p-6"><label className="block text-sm">Email<input required type="email" value={email} onChange={e=>setEmail(e.target.value)} className="mt-2 w-full border border-[#2a3646] bg-[#030508] p-3"/></label><label className="block text-sm">Password<input required type="password" value={password} onChange={e=>setPassword(e.target.value)} className="mt-2 w-full border border-[#2a3646] bg-[#030508] p-3"/></label>{error&&<div className="border border-[#ff2d55]/40 p-3 text-sm text-[#ff6b83]">{error}</div>}<button disabled={busy} className="w-full border border-[#00d9ff] p-3 text-[#00d9ff] disabled:opacity-50">{busy?"Signing in…":"Sign in"}</button><a href="/register" className="block text-center text-sm text-[#8a97a8]">Create a new account</a></form></div></main>;
}
