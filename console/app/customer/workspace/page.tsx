"use client";

import { useEffect, useMemo, useState } from "react";
import { getCustomerOrganizations, getCustomerServiceRequests, getCustomerVerification, submitCustomerVerification, requestCustomerAdmission, getOrganizationMembers, getOrganizationInvitations, createOrganizationInvitation, revokeOrganizationInvitation, createCustomerDeviceEnrollmentToken, setApiToken, type CustomerOrganization, type CustomerServiceRequest, type OrganizationMember, type OrganizationInvitation } from "../../../lib/api";

const labels: Record<string,string> = {
  cybersecurity_assessment:"Cybersecurity Assessment", incident_response:"Incident Response", threat_intelligence:"Threat Intelligence",
  brand_protection:"Brand Protection", dark_web_monitoring:"Dark Web Monitoring", soc_mdr:"SOC / MDR", ai_security:"AI Security",
  physical_security:"Physical Security", compliance:"Compliance", other:"Other"
};

function tone(s:string) {
  if (["approved","verified","resolved","closed"].includes(s)) return "border-[#00e07a]/40 bg-[#00e07a]/10 text-[#7df0ad]";
  if (["rejected","suspended","critical"].includes(s)) return "border-[#ff2d55]/40 bg-[#ff2d55]/10 text-[#ff6b83]";
  if (["pending","review","submitted","in_progress","high"].includes(s)) return "border-[#ffb020]/40 bg-[#ffb020]/10 text-[#ffd27a]";
  return "border-[#2a3646] bg-[#0b242a]/75 text-[#8a97a8]";
}

export default function CustomerWorkspace() {
  const [token,setToken]=useState("");
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
  const [deviceBusy,setDeviceBusy]=useState(false);
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
        const [v,m,i]=await Promise.all([getCustomerVerification(current),getOrganizationMembers(current),getOrganizationInvitations(current)]);
        setVerification(v.verifications); setMembers(m.members); setInvitations(i.invitations);
      } else { setVerification([]); setMembers([]); setInvitations([]); }
    } catch(e) { setError(e instanceof Error ? e.message : "Unable to load customer workspace"); }
    finally { setLoading(false); }
  }

  useEffect(()=>{
    const t=sessionStorage.getItem("cyclothone_access_token")||"";
    setToken(t); setApiToken(t); void load();
  },[]);

  const org=orgs.find(x=>x.id===selected) || null;
  async function selectOrganization(id:string) {
    setSelected(id); setInviteToken(null);
    try {
      const [v,m,i]=await Promise.all([getCustomerVerification(id),getOrganizationMembers(id),getOrganizationInvitations(id)]);
      setVerification(v.verifications); setMembers(m.members); setInvitations(i.invitations);
    } catch(e) { setError(e instanceof Error ? e.message : "Unable to load organization membership"); }
  }
  async function submitVerification() {
    if(!selected) return;
    setVerificationBusy(true); setError(null);
    try {
      await submitCustomerVerification(selected,verificationType,provider,reference);
      const v=await getCustomerVerification(selected); setVerification(v.verifications);
      setProvider(""); setReference("");
    } catch(e) { setError(e instanceof Error ? e.message : "Unable to submit verification"); }
    finally { setVerificationBusy(false); }
  }
  async function requestAdmission() {
    if(!selected) return;
    setVerificationBusy(true); setError(null);
    try {
      await requestCustomerAdmission(selected);
      await load();
    } catch(e) { setError(e instanceof Error ? e.message : "Unable to request admission"); }
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
  async function enrollDevice() {
    if(!selected || !org?.tenant_id || org.admission_status !== "approved") return;
    setDeviceBusy(true); setError(null);
    try {
      const result=await createCustomerDeviceEnrollmentToken(selected);
      window.location.href=`cyclothone://enroll?token=${encodeURIComponent(result.token)}`;
    } catch(e) { setError(e instanceof Error ? e.message : "Unable to start device enrollment"); }
    finally { setDeviceBusy(false); }
  }

  async function revokeInvitation(id:string) {
    setMemberBusy(true); setError(null);
    try { await revokeOrganizationInvitation(selected,id); const i=await getOrganizationInvitations(selected); setInvitations(i.invitations); }
    catch(e) { setError(e instanceof Error ? e.message : "Unable to revoke invitation"); }
    finally { setMemberBusy(false); }
  }

  const orgRequests=useMemo(()=>requests.filter(x=>x.organization_id===selected),[requests,selected]);
  const counts=useMemo(()=>({
    total:orgRequests.length,
    active:orgRequests.filter(x=>["submitted","triage","accepted","in_progress","blocked"].includes(x.status)).length,
    resolved:orgRequests.filter(x=>["resolved","closed"].includes(x.status)).length,
  }),[orgRequests]);

  return <main className="relative min-h-screen overflow-hidden bg-[#021014] text-[#e8f5f3]"><div aria-hidden="true" className="pointer-events-none absolute inset-0"><div className="absolute inset-0 bg-[radial-gradient(ellipse_at_50%_0%,rgba(15,94,100,.38),transparent_45%),linear-gradient(180deg,#031a20_0%,#021014_55%,#01090c_100%)]"/><div className="absolute -left-[10%] top-[22%] h-[55%] w-[120%] rounded-[50%] border border-[#4fc4bd]/10 opacity-60 rotate-[-4deg]"/><div className="absolute -left-[8%] top-[32%] h-[48%] w-[116%] rounded-[50%] border border-[#4fc4bd]/[.06] rotate-[3deg]"/></div>
    <header className="relative z-10 flex h-16 items-center justify-between border-b border-white/10 bg-[#04161b]/70 px-5 backdrop-blur-2xl md:px-8">
      <div><a href="/" className="font-semibold tracking-[-.02em]">Cyclothone</a><span className="ml-3 text-[10px] uppercase tracking-[.18em] text-[#62888a]">Customer workspace</span></div>
      <div className="flex gap-2"><a href="/customer/cases" className="rounded-full border border-white/10 px-3 py-2 text-[10px]">Security cases</a><a href="/request-service" className="rounded-full border border-[#4fc4bd]/35 px-3 py-1.5 text-[11px] text-[#70d3ca]">Request service</a><button onClick={()=>void load()} className="rounded-full border border-white/10 px-3 py-1.5 text-[11px] text-[#8a97a8]">Refresh</button></div>
    </header>

    {error && <div className="mx-auto max-w-7xl px-5 pt-5"><div className="border border-[#ff2d55]/40 bg-[#ff2d55]/5 p-3 text-xs text-[#ff6b83]">{error}</div></div>}

    <div className="relative z-10 mx-auto max-w-7xl p-5 md:p-8">
      {loading ? <div className="rounded-[2rem] border border-white/10 bg-[#06181e]/55 p-8 text-center text-xs text-[#5a6675]">Loading live workspace…</div> :
      !orgs.length ? <div className="rounded-[2rem] border border-dashed border-white/10 bg-[#06181e]/60 p-10 text-center backdrop-blur-xl"><h1 className="text-xl font-semibold">No organization workspace yet</h1><p className="mx-auto mt-2 max-w-lg text-xs text-[#5a6675]">Create an account and organization first. Workspace provisioning occurs only after the real admission and verification process.</p><div className="mt-5"><a href="/register" className="rounded-full border border-[#4fc4bd]/35 px-4 py-2 text-xs text-[#70d3ca]">Create organization</a></div></div> :
      <div className="grid gap-5 lg:grid-cols-[250px_1fr]">
        <aside className="border border-white/10 bg-[#06181e]/65 backdrop-blur-xl p-3">
          <div className="mb-3 px-2 text-[9px] uppercase tracking-[.16em] text-[#5a6675]">Organizations</div>
          {orgs.map(o=><button key={o.id} onClick={()=>void selectOrganization(o.id)} className={"mb-2 w-full rounded-[1.25rem] border p-3 text-left "+(o.id===selected?"border-[#00d9ff]/60 bg-[#0b242a]/75":"border-white/10")}>
            <div className="truncate text-xs font-medium">{o.legal_name}</div><div className="mt-1 text-[10px] text-[#5a6675]">{o.organization_type} · {o.country_code||"—"}</div><div className={"mt-2 inline-block rounded border px-1.5 py-0.5 font-mono text-[9px] "+tone(o.admission_status)}>{o.admission_status}</div>
          </button>)}
        </aside>

        <section className="space-y-5">
          <div className="rounded-[2rem] border border-white/10 bg-[#06181e]/65 p-5 shadow-[0_30px_100px_rgba(0,0,0,.28)] backdrop-blur-xl">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div><div className="text-[9px] uppercase tracking-[.16em] text-[#5a6675]">Workspace</div><h1 className="mt-1 text-2xl font-semibold">{org?.legal_name}</h1><div className="mt-1 text-xs text-[#8a97a8]">{org?.organization_type} · {org?.website_domain||"domain not provided"} · {org?.country_code||"country not provided"}</div></div>
              <div className="text-right"><div className={"inline-block rounded border px-2 py-1 font-mono text-[9px] "+tone(org?.admission_status||"")}>{org?.admission_status||"unknown"}</div><div className="mt-2 text-[10px] text-[#5a6675]">Secure workspace · {org?.tenant_id ? "active" : "pending"}</div></div>
            </div>
            <div className="mt-5 grid gap-3 sm:grid-cols-3">
              <div className="rounded-[1.25rem] border border-white/10 bg-white/[.02] p-3"><div className="font-mono text-2xl">{counts.total}</div><div className="text-[10px] uppercase tracking-[.12em] text-[#5a6675]">Service requests</div></div>
              <div className="border border-white/10 p-3"><div className="font-mono text-2xl">{counts.active}</div><div className="text-[10px] uppercase tracking-[.12em] text-[#5a6675]">Active</div></div>
              <div className="border border-white/10 p-3"><div className="font-mono text-2xl">{counts.resolved}</div><div className="text-[10px] uppercase tracking-[.12em] text-[#5a6675]">Resolved</div></div>
            </div>
          </div>

          {org?.admission_status === "approved" && org?.tenant_id && <div className="rounded-[1.75rem] border border-[#4fc4bd]/20 bg-[#06181e]/65 p-5 backdrop-blur-xl">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div><div className="text-[9px] uppercase tracking-[.16em] text-[#5a6675]">Endpoint protection</div><h2 className="mt-1 text-lg font-semibold">Protect this device</h2><p className="mt-1 max-w-xl text-[11px] text-[#8a97a8]">Open the Cyclothone Desktop app and complete one-time secure enrollment. The private device key stays on the computer.</p></div>
              <button disabled={deviceBusy} onClick={()=>void enrollDevice()} className="rounded-full border border-[#4fc4bd]/45 bg-[#0b242a] px-4 py-2 text-[11px] text-[#70d3ca] disabled:opacity-40">{deviceBusy ? "Starting…" : "Open Cyclothone Desktop"}</button>
            </div>
          </div>}

          <div className="grid gap-5 xl:grid-cols-2">
            <div className="rounded-[1.75rem] border border-white/10 bg-[#06181e]/65 p-4 backdrop-blur-xl">
              <h2 className="text-xs font-medium">Organization members</h2>
              <div className="mt-3 space-y-2">{members.map(m=><div key={m.user_id} className="flex items-center justify-between border-b border-white/10 py-2"><div><div className="text-[10px] text-[#9ab2b3]">Organization member</div><div className="text-[10px] text-[#5a6675]">{m.created_at ? new Date(m.created_at).toLocaleString() : "—"}</div></div><span className="rounded rounded-full border border-white/10 px-1.5 py-0.5 font-mono text-[9px]">{m.role} · {m.status}</span></div>)}{!members.length&&<div className="text-[11px] text-[#5a6675]">No members returned.</div>}</div>
            </div>
            <div className="rounded-[1.75rem] border border-white/10 bg-[#06181e]/65 p-4 backdrop-blur-xl">
              <h2 className="text-xs font-medium">Invite organization member</h2>
              <div className="mt-3 flex gap-2"><input value={inviteEmail} onChange={e=>setInviteEmail(e.target.value)} type="email" placeholder="member@organization.com" className="min-w-0 flex-1 rounded-full border border-white/10 bg-[#041319]/75 p-2 text-xs"/><select value={inviteRole} onChange={e=>setInviteRole(e.target.value)} className="rounded-full border border-white/10 bg-[#041319]/75 p-2 text-xs"><option>requester</option><option>viewer</option><option>analyst</option><option>developer</option><option>security_admin</option><option>admin</option></select><button disabled={memberBusy||!inviteEmail.trim()} onClick={()=>void inviteMember()} className="rounded-full border border-[#4fc4bd]/35 px-3 text-[10px] text-[#70d3ca] disabled:opacity-40">Invite</button></div>
              {inviteToken&&<div className="mt-3 border border-[#ffb020]/40 bg-[#ffb020]/5 p-3"><div className="text-[10px] text-[#ffd27a]">One-time invitation token. Deliver it through your trusted channel.</div><div className="mt-2 break-all rounded-xl bg-black/20 p-2 font-mono text-[10px]">{inviteToken}</div></div>}
              <div className="mt-4 space-y-2">{invitations.filter(i=>!i.accepted_at).map(i=><div key={i.id} className="flex items-center justify-between gap-2 border-b border-white/10 py-2"><div><div className="text-xs">{i.email}</div><div className="text-[10px] text-[#5a6675]">{i.role} · expires {new Date(i.expires_at).toLocaleString()}</div></div><button disabled={memberBusy} onClick={()=>void revokeInvitation(i.id)} className="text-[10px] text-[#ff6b83]">Revoke</button></div>)}</div>
            </div>
          </div>

          <div className="grid gap-5 xl:grid-cols-2">
            <div className="border border-white/10 bg-[#06181e]/65 backdrop-blur-xl p-4">
              <h2 className="text-xs font-medium">Assurance & verification</h2>
              <div className="mt-3 flex items-center justify-between border-b border-white/10 py-2"><span className="text-xs">Organization</span><span className={"rounded border px-1.5 py-0.5 font-mono text-[9px] "+tone(org?.verification_status||"")}>{org?.verification_status}</span></div>
              {verification.map(v=><div key={v.id} className="flex items-center justify-between border-b border-white/10 py-2"><span className="text-xs">{v.verification_type}</span><span className={"rounded border px-1.5 py-0.5 font-mono text-[9px] "+tone(v.status)}>{v.status}</span></div>)}
              {!verification.length && <div className="mt-3 text-[11px] text-[#5a6675]">No verification evidence has been submitted.</div>}
              {org?.admission_status !== "approved" && <div className="mt-4 border-t border-white/10 pt-4">
                <div className="text-[10px] uppercase tracking-[.12em] text-[#5a6675]">Submit verification</div>
                <div className="mt-3 grid gap-2 sm:grid-cols-3">
                  <select value={verificationType} onChange={e=>setVerificationType(e.target.value)} className="rounded-full border border-white/10 bg-[#041319]/75 p-2 text-xs">
                    <option value="business">Business</option><option value="government">Government</option><option value="domain">Domain</option>
                  </select>
                  <input value={provider} onChange={e=>setProvider(e.target.value)} placeholder="Verification provider" className="rounded-full border border-white/10 bg-[#041319]/75 p-2 text-xs"/>
                  <input value={reference} onChange={e=>setReference(e.target.value)} placeholder="Evidence/reference" className="rounded-full border border-white/10 bg-[#041319]/75 p-2 text-xs"/>
                </div>
                <button disabled={verificationBusy} onClick={()=>void submitVerification()} className="mt-3 rounded-full border border-[#4fc4bd]/35 px-3 py-2 text-[10px] text-[#70d3ca] disabled:opacity-40">Submit real verification</button>
              </div>}
            </div>

            <div className="border border-white/10 bg-[#06181e]/65 backdrop-blur-xl p-4">
              <h2 className="text-xs font-medium">Workspace state</h2>
              <div className="mt-3 space-y-2 text-xs">
                <div className="flex justify-between border-b border-white/10 py-2"><span className="text-[#5a6675]">Admission</span><span>{org?.admission_status}</span></div>
                <div className="flex justify-between border-b border-white/10 py-2"><span className="text-[#5a6675]">Tenant</span><span>{org?.tenant_id ? "Provisioned" : "Pending"}</span></div>
                <div className="flex justify-between border-b border-white/10 py-2"><span className="text-[#5a6675]">Security services</span><span>{counts.total}</span></div>
              </div>
              {org?.verification_status && ["business_verified","government_verified"].includes(org.verification_status) && org.admission_status !== "approved" && <button disabled={verificationBusy} onClick={()=>void requestAdmission()} className="mt-4 w-full border border-[#ffb347] px-3 py-2 text-[10px] text-[#ffb347] disabled:opacity-40">Request workspace admission</button>}
            </div>
          </div>

          <div className="border border-white/10 bg-[#06181e]/65 backdrop-blur-xl p-4">
            <div className="mb-3 flex items-center justify-between"><h2 className="text-xs font-medium">Service requests</h2><a href="/request-service" className="text-[10px] text-[#70d3ca]">+ New request</a></div>
            {!orgRequests.length ? <div className="py-8 text-center text-xs text-[#5a6675]">No service requests recorded for this organization.</div> :
            <div className="divide-y divide-[#1a2330]">{orgRequests.map(r=><div key={r.id} className="py-3"><div className="flex flex-wrap items-center justify-between gap-2"><div className="text-xs font-medium">{labels[r.service_key]||r.service_key}</div><div className="flex gap-2"><span className={"rounded border px-1.5 py-0.5 font-mono text-[9px] "+tone(r.urgency)}>{r.urgency}</span><span className={"rounded border px-1.5 py-0.5 font-mono text-[9px] "+tone(r.status)}>{r.status}</span></div></div><p className="mt-1 text-[11px] text-[#8a97a8]">{r.description}</p><div className="mt-1 font-mono text-[9px] text-[#5a6675]">{new Date(r.created_at).toLocaleString()}</div></div>)}</div>}
          </div>
        </section>
      </div>}
    </div>
  </main>
}