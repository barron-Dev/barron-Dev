"use client";

import { useEffect, useState } from "react";
import { acceptOrganizationInvitation, setApiToken } from "../../../lib/api";

export default function AcceptInvitation() {
  const [token,setToken]=useState("");
  const [busy,setBusy]=useState(false);
  const [message,setMessage]=useState("");
  const [error,setError]=useState("");
  useEffect(()=>{
    const t=sessionStorage.getItem("cyclothone_access_token")||"";
    setApiToken(t);
    const q=new URLSearchParams(window.location.search).get("token")||"";
    setToken(q);
  },[]);
  async function accept(){
    setBusy(true);setError("");setMessage("");
    try{
      const r=await acceptOrganizationInvitation(token);
      setMessage("Invitation accepted. Your organization membership is now active.");
      window.setTimeout(()=>window.location.assign("/customer/workspace"),600);
    }catch(e){setError(e instanceof Error?e.message:"Unable to accept invitation");}
    finally{setBusy(false);}
  }
  return <main className="min-h-screen bg-[#05070a] text-[#e8eef6] flex items-center justify-center p-5">
    <section className="w-full max-w-lg border border-[#1a2330] bg-[#0a0e14] p-6">
      <a href="/" className="text-sm font-semibold">Cyclothone</a>
      <div className="mt-6 text-[9px] uppercase tracking-[.16em] text-[#5a6675]">Organization invitation</div>
      <h1 className="mt-2 text-2xl font-semibold">Join an organization</h1>
      <p className="mt-2 text-xs leading-5 text-[#8a97a8]">Sign in with the email address that received this invitation. Acceptance is checked against the authenticated account email.</p>
      {!token&&<div className="mt-5"><label className="text-[10px] text-[#8a97a8]">Invitation token</label><input value={token} onChange={e=>setToken(e.target.value)} className="mt-1 w-full border border-[#2a3646] bg-[#030508] p-3 font-mono text-xs"/></div>}
      {error&&<div className="mt-4 border border-[#ff2d55]/40 bg-[#ff2d55]/5 p-3 text-xs text-[#ff6b83]">{error}</div>}
      {message&&<div className="mt-4 border border-[#00e07a]/40 bg-[#00e07a]/5 p-3 text-xs text-[#7df0ad]">{message}</div>}
      <button disabled={busy||token.length<20} onClick={()=>void accept()} className="mt-5 w-full border border-[#00d9ff] px-4 py-3 text-xs text-[#00d9ff] disabled:opacity-40">{busy?"Accepting…":"Accept invitation"}</button>
      <div className="mt-4 text-center text-[10px] text-[#5a6675]"><a href="/login" className="text-[#00d9ff]">Sign in</a> if you are not authenticated.</div>
    </section>
  </main>;
}
