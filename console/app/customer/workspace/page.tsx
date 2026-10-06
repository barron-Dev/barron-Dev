"use client";

import { useEffect, useMemo, useState } from "react";
import {
  getCustomerOrganizations,
  getCustomerServiceRequests,
  getCustomerVerification,
  submitCustomerVerification,
  requestCustomerAdmission,
  getOrganizationMembers,
  getOrganizationInvitations,
  createOrganizationInvitation,
  revokeOrganizationInvitation,
  type CustomerOrganization,
  type CustomerServiceRequest,
  type OrganizationMember,
  type OrganizationInvitation,
} from "../../../lib/api";

const labels: Record<string,string> = {
  cybersecurity_assessment:"Cybersecurity Assessment", incident_response:"Incident Response", threat_intelligence:"Threat Intelligence",
  brand_protection:"Brand Protection", dark_web_monitoring:"Dark Web Monitoring", soc_mdr:"SOC / MDR", ai_security:"AI Security",
  physical_security:"Physical Security", compliance:"Compliance", hunting:"Threat Hunting", investigation:"Investigation",
  recovery:"Recovery", web_intelligence:"Web Intelligence", scam_monitoring:"Scam Monitoring",
  mobile_digital_intelligence:"Mobile & Digital Intelligence", other:"Other"
};

function tone(s:string) {
  if (["approved","verified","resolved","closed"].includes(s)) return "text-[#7df0ad]";
  if (["rejected","suspended","critical"].includes(s)) return "text-[#ff6b83]";
  if (["pending","review","submitted","in_progress","high"].includes(s)) return "text-[#ffd27a]";
  return "text-[#9ab0b6]";
}

export default function CustomerWorkspace() {
  const [orgs,setOrgs]=useState<CustomerOrganization[]>([]);
  const [requests,setRequests]=useState<CustomerServiceRequest[]>([]);
  const [selected,setSelected]=useState("");
  const [verification,setVerification]=useState<any[]>([]);
  const [verificationType,setVerificationType]=useState("business");
  const [provider,setProvider]=useState("");
  const [reference,setReference]=useState("");
  const [verificationBusy,setVerificationBusy]=useState(false);
  const [members,setMembers]=useState<OrganizationMember[]>([]);
  const [invitations,setInvitations]=useState<OrganizationInvitation[]>([]);
  const [inviteEmail,setInviteEmail]=useState("");
  const [inviteRole,setInviteRole]=useState("requester");
  const [inviteToken,setInviteToken]=useState<string|null>(null);
  const [memberBusy,setMemberBusy]=useState(false);
  const [loading,setLoading]=useState(true);
  const [error,setError]=useState<string|null>(null);

  async function load() {
    setLoading(true); setError(null);
    try {
      const [o,r]=await Promise.all([getCustomerOrganizations(),getCustomerServiceRequests()]);
      setOrgs(o.organizations); setRequests(r.service_requests);
      const current=selected && o.organizations.some(x=>x.id===selected) ? selected : o.organizations[0]?.id || "";
      setSelected(current);
      if(current) {
        const [v,m,i]=await Promise.all([
          getCustomerVerification(current),
          getOrganizationMembers(current),
          getOrganizationInvitations(current)
        ]);
        setVerification(v.verifications); setMembers(m.members); setInvitations(i.invitations);
      } else {
        setVerification([]); setMembers([]); setInvitations([]);
      }
    } catch(e) {
      setError(e instanceof Error ? e.message : "Unable to load customer workspace");
    } finally { setLoading(false); }
  }

  useEffect(()=>{ void load(); },[]);

  const org=orgs.find(x=>x.id===selected) || null;

  async function selectOrganization(id:string) {
    setSelected(id); setInviteToken(null); setError(null);
    try {
      const [v,m,i]=await Promise.all([
        getCustomerVerification(id),getOrganizationMembers(id),getOrganizationInvitations(id)
      ]);
      setVerification(v.verifications); setMembers(m.members); setInvitations(i.invitations);
    } catch(e) {
      setError(e instanceof Error ? e.message : "Unable to load organization");
    }
  }

  async function submitVerification() {
    if(!selected) return;
    setVerificationBusy(true); setError(null);
    try {
      await submitCustomerVerification(selected,verificationType,provider,reference);
      const v=await getCustomerVerification(selected);
      setVerification(v.verifications);
      setProvider(""); setReference("");
    } catch(e) {
      setError(e instanceof Error ? e.message : "Unable to submit verification");
    } finally { setVerificationBusy(false); }
  }

  async function requestAdmission() {
    if(!selected) return;
    setVerificationBusy(true); setError(null);
    try { await requestCustomerAdmission(selected); await load(); }
    catch(e) { setError(e instanceof Error ? e.message : "Unable to request admission"); }
    finally { setVerificationBusy(false); }
  }

  async function inviteMember() {
    if(!selected || !inviteEmail.trim()) return;
    setMemberBusy(true); setError(null); setInviteToken(null);
    try {
      const r=await createOrganizationInvitation(selected,inviteEmail,inviteRole);
      setInviteToken(r.invite_token); setInviteEmail("");
      const i=await getOrganizationInvitations(selected); setInvitations(i.invitations);
    } catch(e) { setError(e instanceof Error ? e.message : "Unable to create invitation"); }
    finally { setMemberBusy(false); }
  }

  async function revokeInvitation(id:string) {
    setMemberBusy(true); setError(null);
    try {
      await revokeOrganizationInvitation(selected,id);
      const i=await getOrganizationInvitations(selected); setInvitations(i.invitations);
    } catch(e) { setError(e instanceof Error ? e.message : "Unable to revoke invitation"); }
    finally { setMemberBusy(false); }
  }

  const orgRequests=useMemo(()=>requests.filter(x=>x.organization_id===selected),[requests,selected]);
  const counts=useMemo(()=>({
    total:orgRequests.length,
    active:orgRequests.filter(x=>["submitted","triage","accepted","in_progress","blocked"].includes(x.status)).length,
    resolved:orgRequests.filter(x=>["resolved","closed"].includes(x.status)).length,
  }),[orgRequests]);

  return <main className="cyclo-water min-h-screen text-[#e8f5f3]">
    <header className="relative z-10 flex h-16 items-center justify-between border-b border-white/10 bg-[#02090e]/70 px-5 backdrop-blur-2xl md:px-8">
      <div><a href="/customer/overview" className="cyclo-mark font-semibold tracking-[-.02em]">◌ CYCLOTHONE</a><span className="ml-3 text-[10px] uppercase tracking-[.18em] text-[#62888a]">Command center</span></div>
      <div className="flex gap-2"><a href="/customer/cases" className="cyclo-pill px-3 py-2 text-[10px] text-[#9ab0b6]">Security cases</a><a href="/request-service" className="cyclo-pill px-3 py-1.5 text-[11px] text-[#c2f35a]">Request service</a><button onClick={()=>void load()} className="cyclo-pill px-3 py-1.5 text-[11px] text-[#9ab0b6]">Refresh</button></div>
    </header>

    {error && <div className="relative z-10 mx-auto max-w-6xl px-5 pt-5"><div className="border-l-2 border-[#ff3d67] bg-[#250910]/40 px-4 py-3 text-xs text-[#ff8ba0]">{error}</div></div>}

    <div className="relative z-10 mx-auto max-w-6xl px-5 py-8 md:py-10">
      {loading ? <div className="py-16 text-center text-xs text-[#69858d]">Loading live workspace…</div> :
      !orgs.length ? <div className="py-16 text-center"><h1 className="text-xl font-semibold">No organization workspace yet</h1><p className="mx-auto mt-3 max-w-lg text-xs leading-6 text-[#69858d]">Create an organization only when a protected service needs an organizational security boundary.</p><a href="/customer/profile" className="mt-5 inline-block text-xs text-[#c2f35a]">Create organization →</a></div> :
      <div>
        <div className="mb-8 flex flex-wrap items-end justify-between gap-5 border-b border-white/10 pb-6">
          <div>
            <div className="text-[9px] uppercase tracking-[.2em] text-[#4f8494]">Workspace</div>
            <h1 className="mt-2 text-3xl font-semibold">{org?.legal_name}</h1>
            <p className="mt-2 text-xs text-[#8ca6ad]">{org?.organization_type} · {org?.website_domain||"domain not provided"} · {org?.country_code||"country not provided"}</p>
          </div>
          <div className="text-right text-xs"><div className={tone(org?.admission_status||"")}>{org?.admission_status||"unknown"}</div><div className="mt-1 text-[10px] text-[#5a6675]">Tenant {org?.tenant_id ? "provisioned" : "pending"}</div></div>
        </div>

        <div className="mb-9 flex flex-wrap gap-x-10 gap-y-3 border-b border-white/10 pb-5 text-xs">
          <span><strong className="mr-2 font-mono text-lg">{counts.total}</strong><span className="text-[#69858d]">service requests</span></span>
          <span><strong className="mr-2 font-mono text-lg">{counts.active}</strong><span className="text-[#69858d]">active</span></span>
          <span><strong className="mr-2 font-mono text-lg">{counts.resolved}</strong><span className="text-[#69858d]">resolved</span></span>
        </div>

        <section className="border-b border-white/10 pb-8">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div><h2 className="text-sm font-medium">Assurance & verification</h2><p className="mt-1 text-[11px] leading-5 text-[#69858d]">Submit real evidence so Cyclothone can review and admit this workspace.</p></div>
            <span className={"text-xs "+tone(org?.verification_status||"")}>{org?.verification_status||"pending"}</span>
          </div>
          {verification.length>0 && <div className="mt-5 space-y-2">{verification.map(v=><div key={v.id} className="flex flex-wrap justify-between gap-3 border-b border-white/10 py-3 text-xs"><span>{v.verification_type}</span><span className={tone(v.status)}>{v.status}</span></div>)}</div>}
          {!verification.length && <p className="mt-5 text-[11px] text-[#5a6675]">No verification evidence has been submitted.</p>}
          {org?.admission_status !== "approved" && <div className="mt-6 max-w-3xl">
            <div className="mb-3 text-[10px] uppercase tracking-[.15em] text-[#5a6675]">New verification</div>
            <div className="grid gap-3 md:grid-cols-[160px_1fr_1fr_auto]">
              <select value={verificationType} onChange={e=>setVerificationType(e.target.value)} className="border-b border-white/15 bg-transparent p-2 text-xs outline-none"><option value="business">Business</option><option value="government">Government</option><option value="domain">Domain</option></select>
              <input value={provider} onChange={e=>setProvider(e.target.value)} placeholder="Provider" className="border-b border-white/15 bg-transparent p-2 text-xs outline-none"/>
              <input value={reference} onChange={e=>setReference(e.target.value)} placeholder="Evidence / reference" className="border-b border-white/15 bg-transparent p-2 text-xs outline-none"/>
              <button disabled={verificationBusy} onClick={()=>void submitVerification()} className="px-3 py-2 text-xs text-[#c2f35a] disabled:opacity-40">{verificationBusy?"Submitting…":"Submit →"}</button>
            </div>
          </div>}
          {org?.verification_status && ["business_verified","government_verified"].includes(org.verification_status) && org.admission_status !== "approved" && <button disabled={verificationBusy} onClick={()=>void requestAdmission()} className="mt-6 border-b border-[#ffb347] pb-1 text-xs text-[#ffb347] disabled:opacity-40">Request workspace admission →</button>}
        </section>

        <section className="grid gap-10 border-b border-white/10 py-8 md:grid-cols-2">
          <div>
            <h2 className="text-sm font-medium">Organization members</h2>
            <div className="mt-4 space-y-2">{members.map(m=><div key={m.user_id} className="flex justify-between gap-3 border-b border-white/10 py-3 text-xs"><span>Organization member <span className="ml-2 text-[#5a6675]">{m.created_at?new Date(m.created_at).toLocaleString():"—"}</span></span><span>{m.role} · {m.status}</span></div>)}</div>
            {!members.length && <div className="mt-4 text-[11px] text-[#5a6675]">No members returned.</div>}
          </div>
          <div>
            <h2 className="text-sm font-medium">Invite member</h2>
            <div className="mt-4 grid gap-2 sm:grid-cols-[1fr_130px_auto]">
              <input value={inviteEmail} onChange={e=>setInviteEmail(e.target.value)} type="email" placeholder="member@organization.com" className="border-b border-white/15 bg-transparent p-2 text-xs outline-none"/>
              <select value={inviteRole} onChange={e=>setInviteRole(e.target.value)} className="border-b border-white/15 bg-transparent p-2 text-xs outline-none"><option>requester</option><option>viewer</option><option>analyst</option><option>developer</option><option>security_admin</option><option>admin</option></select>
              <button disabled={memberBusy||!inviteEmail.trim()} onClick={()=>void inviteMember()} className="px-3 py-2 text-xs text-[#70d3ca] disabled:opacity-40">Invite →</button>
            </div>
            {inviteToken&&<div className="mt-4 border-l-2 border-[#ffb020] bg-[#ffb020]/5 p-3 text-[10px] text-[#ffd27a]">One-time invitation token: <span className="break-all font-mono">{inviteToken}</span></div>}
            <div className="mt-4 space-y-2">{invitations.filter(i=>!i.accepted_at).map(i=><div key={i.id} className="flex justify-between gap-3 border-b border-white/10 py-3 text-xs"><span>{i.email}</span><button disabled={memberBusy} onClick={()=>void revokeInvitation(i.id)} className="text-[#ff6b83]">Revoke</button></div>)}</div>
          </div>
        </section>

        <section className="py-8">
          <div className="flex items-center justify-between border-b border-white/10 pb-4"><h2 className="text-sm font-medium">Service requests</h2><a href="/request-service" className="text-xs text-[#c2f35a]">+ New request</a></div>
          {!orgRequests.length ? <div className="py-10 text-center text-xs text-[#5a6675]">No service requests recorded for this organization.</div> :
          <div className="divide-y divide-[#1a2330]">{orgRequests.map(r=><div key={r.id} className="py-4"><div className="flex flex-wrap justify-between gap-3"><div className="text-xs font-medium">{labels[r.service_key]||r.service_key}</div><div className="text-[10px]"><span className={"mr-3 "+tone(r.urgency)}>{r.urgency}</span><span className={tone(r.status)}>{r.status}</span></div></div><p className="mt-2 whitespace-pre-line text-[11px] leading-5 text-[#8a97a8]">{r.description}</p><div className="mt-2 font-mono text-[9px] text-[#5a6675]">{new Date(r.created_at).toLocaleString()}</div></div>)}</div>}
        </section>
      </div>}
    </div>
  </main>;
}
