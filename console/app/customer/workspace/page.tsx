"use client";

import { useEffect, useMemo, useState } from "react";
import { getCustomerOrganizations, getCustomerServiceRequests, getCustomerVerification, getOrganizationMembers, getOrganizationInvitations, createOrganizationInvitation, revokeOrganizationInvitation, setApiToken, type CustomerOrganization, type CustomerServiceRequest, type OrganizationMember, type OrganizationInvitation } from "../../lib/api";

const labels: Record<string,string> = {
  cybersecurity_assessment:"Cybersecurity Assessment", incident_response:"Incident Response", threat_intelligence:"Threat Intelligence",
  brand_protection:"Brand Protection", dark_web_monitoring:"Dark Web Monitoring", soc_mdr:"SOC / MDR", ai_security:"AI Security",
  physical_security:"Physical Security", compliance:"Compliance", other:"Other"
};

function tone(s:string) {
  if (["approved","verified","resolved","closed"].includes(s)) return "border-[#00e07a]/40 bg-[#00e07a]/10 text-[#7df0ad]";
  if (["rejected","suspended","critical"].includes(s)) return "border-[#ff2d55]/40 bg-[#ff2d55]/10 text-[#ff6b83]";
  if (["pending","review","submitted","in_progress","high"].includes(s)) return "border-[#ffb020]/40 bg-[#ffb020]/10 text-[#ffd27a]";
  return "border-[#2a3646] bg-[#111823] text-[#8a97a8]";
}

export default function CustomerWorkspace() {
  const [token,setToken]=useState("");
  const [orgs,setOrgs]=useState<CustomerOrganization[]>([]);
  const [requests,setRequests]=useState<CustomerServiceRequest[]>([]);
  const [selected,setSelected]=useState("");
  const [verification,setVerification]=useState<any[]>([]);
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

  return <main className="min-h-screen bg-[#05070a] text-[#e8eef6]">
    <header className="flex h-14 items-center justify-between border-b border-[#1a2330] bg-[#0a0e14] px-5">
      <div><a href="/" className="font-semibold">Cyclothone</a><span className="ml-3 text-[10px] uppercase tracking-[.16em] text-[#5a6675]">Customer workspace</span></div>
      <div className="flex gap-2"><a href="/customer/cases" className="border border-[#2a3646] px-3 py-2 text-[10px]">Security cases</a><a href="/request-service" className="border border-[#00d9ff] px-3 py-1.5 text-[11px] text-[#00d9ff]">Request service</a><button onClick={()=>void load()} className="border border-[#2a3646] px-3 py-1.5 text-[11px] text-[#8a97a8]">Refresh</button></div>
    </header>

    {error && <div className="mx-auto max-w-7xl px-5 pt-5"><div className="border border-[#ff2d55]/40 bg-[#ff2d55]/5 p-3 text-xs text-[#ff6b83]">{error}</div></div>}

    <div className="mx-auto max-w-7xl p-5">
      {loading ? <div className="border border-[#1a2330] p-8 text-center text-xs text-[#5a6675]">Loading live workspace…</div> :
      !orgs.length ? <div className="border border-dashed border-[#1a2330] p-10 text-center"><h1 className="text-xl font-semibold">No organization workspace yet</h1><p className="mx-auto mt-2 max-w-lg text-xs text-[#5a6675]">Create an account and organization first. Workspace provisioning occurs only after the real admission and verification process.</p><div className="mt-5"><a href="/register" className="border border-[#00d9ff] px-4 py-2 text-xs text-[#00d9ff]">Create organization</a></div></div> :
      <div className="grid gap-5 lg:grid-cols-[250px_1fr]">
        <aside className="border border-[#1a2330] bg-[#0a0e14] p-3">
          <div className="mb-3 px-2 text-[9px] uppercase tracking-[.16em] text-[#5a6675]">Organizations</div>
          {orgs.map(o=><button key={o.id} onClick={()=>void selectOrganization(o.id)} className={"mb-1 w-full border p-3 text-left "+(o.id===selected?"border-[#00d9ff]/60 bg-[#111823]":"border-[#1a2330]")}>
            <div className="truncate text-xs font-medium">{o.legal_name}</div><div className="mt-1 text-[10px] text-[#5a6675]">{o.organization_type} · {o.country_code||"—"}</div><div className={"mt-2 inline-block rounded border px-1.5 py-0.5 font-mono text-[9px] "+tone(o.admission_status)}>{o.admission_status}</div>
          </button>)}
        </aside>

        <section className="space-y-5">
          <div className="border border-[#1a2330] bg-[#0a0e14] p-5">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div><div className="text-[9px] uppercase tracking-[.16em] text-[#5a6675]">Workspace</div><h1 className="mt-1 text-2xl font-semibold">{org?.legal_name}</h1><div className="mt-1 text-xs text-[#8a97a8]">{org?.organization_type} · {org?.website_domain||"domain not provided"} · {org?.country_code||"country not provided"}</div></div>
              <div className="text-right"><div className={"inline-block rounded border px-2 py-1 font-mono text-[9px] "+tone(org?.admission_status||"")}>{org?.admission_status||"unknown"}</div><div className="mt-2 text-[10px] text-[#5a6675]">Tenant {org?.tenant_id ? org.tenant_id : "not provisioned"}</div></div>
            </div>
            <div className="mt-5 grid gap-3 sm:grid-cols-3">
              <div className="border border-[#1a2330] p-3"><div className="font-mono text-2xl">{counts.total}</div><div className="text-[10px] uppercase tracking-[.12em] text-[#5a6675]">Service requests</div></div>
              <div className="border border-[#1a2330] p-3"><div className="font-mono text-2xl">{counts.active}</div><div className="text-[10px] uppercase tracking-[.12em] text-[#5a6675]">Active</div></div>
              <div className="border border-[#1a2330] p-3"><div className="font-mono text-2xl">{counts.resolved}</div><div className="text-[10px] uppercase tracking-[.12em] text-[#5a6675]">Resolved</div></div>
            </div>
          </div>

          <div className="grid gap-5 xl:grid-cols-2">
            <div className="border border-[#1a2330] bg-[#0a0e14] p-4">
              <h2 className="text-xs font-medium">Organization members</h2>
              <div className="mt-3 space-y-2">{members.map(m=><div key={m.user_id} className="flex items-center justify-between border-b border-[#1a2330] py-2"><div><div className="font-mono text-[10px]">{m.user_id}</div><div className="text-[10px] text-[#5a6675]">{m.created_at ? new Date(m.created_at).toLocaleString() : "—"}</div></div><span className="rounded border border-[#2a3646] px-1.5 py-0.5 font-mono text-[9px]">{m.role} · {m.status}</span></div>)}{!members.length&&<div className="text-[11px] text-[#5a6675]">No members returned.</div>}</div>
            </div>
            <div className="border border-[#1a2330] bg-[#0a0e14] p-4">
              <h2 className="text-xs font-medium">Invite organization member</h2>
              <div className="mt-3 flex gap-2"><input value={inviteEmail} onChange={e=>setInviteEmail(e.target.value)} type="email" placeholder="member@organization.com" className="min-w-0 flex-1 border border-[#2a3646] bg-[#030508] p-2 text-xs"/><select value={inviteRole} onChange={e=>setInviteRole(e.target.value)} className="border border-[#2a3646] bg-[#030508] p-2 text-xs"><option>requester</option><option>viewer</option><option>analyst</option><option>developer</option><option>security_admin</option><option>admin</option></select><button disabled={memberBusy||!inviteEmail.trim()} onClick={()=>void inviteMember()} className="border border-[#00d9ff] px-3 text-[10px] text-[#00d9ff] disabled:opacity-40">Invite</button></div>
              {inviteToken&&<div className="mt-3 border border-[#ffb020]/40 bg-[#ffb020]/5 p-3"><div className="text-[10px] text-[#ffd27a]">One-time invitation token. It is not stored in plaintext; deliver it through a trusted channel.</div><div className="mt-2 break-all font-mono text-[10px]">{inviteToken}</div></div>}
              <div className="mt-4 space-y-2">{invitations.filter(i=>!i.accepted_at).map(i=><div key={i.id} className="flex items-center justify-between gap-2 border-b border-[#1a2330] py-2"><div><div className="text-xs">{i.email}</div><div className="text-[10px] text-[#5a6675]">{i.role} · expires {new Date(i.expires_at).toLocaleString()}</div></div><button disabled={memberBusy} onClick={()=>void revokeInvitation(i.id)} className="text-[10px] text-[#ff6b83]">Revoke</button></div>)}</div>
            </div>
          </div>

          <div className="grid gap-5 xl:grid-cols-2">
            <div className="border border-[#1a2330] bg-[#0a0e14] p-4">
              <h2 className="text-xs font-medium">Assurance & verification</h2>
              <div className="mt-3 flex items-center justify-between border-b border-[#1a2330] py-2"><span className="text-xs">Organization</span><span className={"rounded border px-1.5 py-0.5 font-mono text-[9px] "+tone(org?.verification_status||"")}>{org?.verification_status}</span></div>
              {verification.map(v=><div key={v.id} className="flex items-center justify-between border-b border-[#1a2330] py-2"><span className="text-xs">{v.verification_type}</span><span className={"rounded border px-1.5 py-0.5 font-mono text-[9px] "+tone(v.status)}>{v.status}</span></div>)}
              {!verification.length && <div className="mt-3 text-[11px] text-[#5a6675]">No verification evidence has been submitted.</div>}
            </div>

            <div className="border border-[#1a2330] bg-[#0a0e14] p-4">
              <h2 className="text-xs font-medium">Workspace state</h2>
              <div className="mt-3 space-y-2 text-xs">
                <div className="flex justify-between border-b border-[#1a2330] py-2"><span className="text-[#5a6675]">Admission</span><span>{org?.admission_status}</span></div>
                <div className="flex justify-between border-b border-[#1a2330] py-2"><span className="text-[#5a6675]">Tenant</span><span>{org?.tenant_id ? "Provisioned" : "Pending"}</span></div>
                <div className="flex justify-between border-b border-[#1a2330] py-2"><span className="text-[#5a6675]">Security services</span><span>{counts.total}</span></div>
              </div>
            </div>
          </div>

          <div className="border border-[#1a2330] bg-[#0a0e14] p-4">
            <div className="mb-3 flex items-center justify-between"><h2 className="text-xs font-medium">Service requests</h2><a href="/request-service" className="text-[10px] text-[#00d9ff]">+ New request</a></div>
            {!orgRequests.length ? <div className="py-8 text-center text-xs text-[#5a6675]">No service requests recorded for this organization.</div> :
            <div className="divide-y divide-[#1a2330]">{orgRequests.map(r=><div key={r.id} className="py-3"><div className="flex flex-wrap items-center justify-between gap-2"><div className="text-xs font-medium">{labels[r.service_key]||r.service_key}</div><div className="flex gap-2"><span className={"rounded border px-1.5 py-0.5 font-mono text-[9px] "+tone(r.urgency)}>{r.urgency}</span><span className={"rounded border px-1.5 py-0.5 font-mono text-[9px] "+tone(r.status)}>{r.status}</span></div></div><p className="mt-1 text-[11px] text-[#8a97a8]">{r.description}</p><div className="mt-1 font-mono text-[9px] text-[#5a6675]">{new Date(r.created_at).toLocaleString()}</div></div>)}</div>}
          </div>
        </section>
      </div>}
    </div>
  </main>
}