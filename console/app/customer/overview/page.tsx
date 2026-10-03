"use client";

import { useEffect, useState } from "react";
import { getCustomerCases, getCustomerOrganizations, getCustomerServiceRequests, type CustomerCase, type CustomerOrganization, type CustomerServiceRequest } from "../../../lib/api";

const statusTone: Record<string,string> = {
  approved:"text-[#7df0ad] border-[#00e07a]/40",
  verified:"text-[#7df0ad] border-[#00e07a]/40",
  pending:"text-[#ffd27a] border-[#ffb020]/40",
  submitted:"text-[#ffd27a] border-[#ffb020]/40",
  in_progress:"text-[#ffd27a] border-[#ffb020]/40",
  resolved:"text-[#7df0ad] border-[#00e07a]/40",
  closed:"text-[#7df0ad] border-[#00e07a]/40",
  rejected:"text-[#ff6b83] border-[#ff2d55]/40",
};

export default function CustomerOverview() {
  const [orgs,setOrgs]=useState<CustomerOrganization[]>([]);
  const [requests,setRequests]=useState<CustomerServiceRequest[]>([]);
  const [cases,setCases]=useState<CustomerCase[]>([]);
  const [loading,setLoading]=useState(true);
  const [error,setError]=useState("");

  async function load() {
    setLoading(true); setError("");
    try {
      const [o,r,c]=await Promise.all([getCustomerOrganizations(),getCustomerServiceRequests(),getCustomerCases()]);
      setOrgs(o.organizations); setRequests(r.service_requests); setCases(c.cases);
    } catch(e) {
      setError(e instanceof Error ? e.message : "Unable to load your customer workspace");
    } finally { setLoading(false); }
  }

  useEffect(()=>{ void load(); },[]);

  const org=orgs[0] ?? null;
  const active=requests.filter(x=>!["resolved","closed","rejected"].includes(x.status)).length;
  const openCases=cases.filter(x=>!["resolved","closed"].includes(x.case.status)).length;

  return (
    <main className="min-h-screen bg-[#05070a] text-[#e8eef6]">
      <header className="flex min-h-14 flex-wrap items-center justify-between gap-3 border-b border-[#1a2330] bg-[#0a0e14] px-5 py-3">
        <div><a href="https://cyclothone.online" className="font-semibold">Cyclothone</a><span className="ml-3 text-[10px] uppercase tracking-[.16em] text-[#ffb347]">Customer</span></div>
        <nav className="flex gap-2 text-[10px]"><a href="/customer/workspace" className="border border-[#2a3646] px-3 py-2">Workspace</a><a href="/customer/cases" className="border border-[#2a3646] px-3 py-2">Cases</a><a href="/request-service" className="border border-[#00d9ff] px-3 py-2 text-[#00d9ff]">Request service</a></nav>
      </header>

      <div className="mx-auto max-w-6xl px-5 py-10">
        <div className="max-w-2xl">
          <div className="text-[10px] uppercase tracking-[.18em] text-[#5a6675]">Customer workspace</div>
          <h1 className="mt-2 text-3xl font-semibold">{org ? org.legal_name : "Welcome to Cyclothone"}</h1>
          <p className="mt-3 text-sm leading-6 text-[#8a97a8]">Manage your organization, request security services and follow the cases created from those requests.</p>
        </div>

        {error && <div className="mt-6 border border-[#ff2d55]/40 bg-[#ff2d55]/5 p-4 text-xs text-[#ff6b83]">{error}<div className="mt-3"><a href="/login" className="text-[#00d9ff]">Sign in again →</a></div></div>}

        {loading ? <div className="mt-8 border border-[#1a2330] bg-[#0a0e14] p-8 text-center text-xs text-[#5a6675]">Loading your workspace…</div> :
        !org ? <div className="mt-8 border border-dashed border-[#2a3646] bg-[#0a0e14] p-8"><h2 className="text-lg font-medium">Set up your organization</h2><p className="mt-2 max-w-xl text-xs leading-5 text-[#8a97a8]">Create your account and organization first. Verification and admission happen before protected services are provisioned.</p><a href="/customer/profile" className="mt-5 inline-block border border-[#00d9ff] px-4 py-2 text-[11px] text-[#00d9ff]">Create organization →</a></div> :
        <>
          <div className="mt-8 grid gap-px bg-[#1a2330] md:grid-cols-3">
            {[["Organization",org.admission_status || "pending","Admission status"],["Service requests",String(requests.length),active ? active+" active" : "No active requests"],["Security cases",String(cases.length),openCases ? openCases+" open" : "No open cases"]].map(([label,value,meta])=><div key={label} className="bg-[#0a0e14] p-5"><div className="text-[10px] uppercase tracking-[.12em] text-[#5a6675]">{label}</div><div className={"mt-3 text-xl font-medium "+(label==="Organization" ? (statusTone[value] ?? "text-[#e8eef6]") : "text-[#e8eef6]")}>{value}</div><div className="mt-1 text-[10px] text-[#8a97a8]">{meta}</div></div>)}
          </div>

          <div className="mt-8 grid gap-4 md:grid-cols-3">
            <a href="/customer/workspace" className="border border-[#2a3646] bg-[#0a0e14] p-5 hover:border-[#ffb347]"><h2 className="font-medium">Organization</h2><p className="mt-2 text-xs leading-5 text-[#8a97a8]">Verification, members, invitations and workspace status.</p><div className="mt-4 text-[10px] text-[#ffb347]">Open workspace →</div></a>
            <a href="/customer/services" className="border border-[#2a3646] bg-[#0a0e14] p-5 hover:border-[#00d9ff]"><h2 className="font-medium">Security services</h2><p className="mt-2 text-xs leading-5 text-[#8a97a8]">Browse the complete customer service catalog and request an authorized service.</p><div className="mt-4 text-[10px] text-[#00d9ff]">View services →</div></a>
            <a href="/customer/cases" className="border border-[#2a3646] bg-[#0a0e14] p-5 hover:border-[#7df0ad]"><h2 className="font-medium">Security cases</h2><p className="mt-2 text-xs leading-5 text-[#8a97a8]">Track service cases, activity and customer-visible outcomes.</p><div className="mt-4 text-[10px] text-[#7df0ad]">View cases →</div></a>
          </div>

          <section className="mt-8 border border-[#1a2330] bg-[#0a0e14] p-5">
            <div className="flex items-center justify-between"><h2 className="font-medium">Recent service requests</h2><a href="/request-service" className="text-[10px] text-[#00d9ff]">New request</a></div>
            {!requests.length ? <div className="mt-6 text-xs text-[#5a6675]">No service requests yet.</div> :
            <div className="mt-4 divide-y divide-[#1a2330]">{requests.slice(0,5).map(r=><div key={r.id} className="flex flex-wrap items-center justify-between gap-3 py-3"><div><div className="text-xs font-medium">{r.service_key}</div><div className="mt-1 text-[10px] text-[#5a6675]">{new Date(r.created_at).toLocaleString()}</div></div><span className={"rounded border px-2 py-1 text-[9px] "+(statusTone[r.status] ?? "text-[#8a97a8] border-[#2a3646]")}>{r.status}</span></div>)}</div>}
          </section>
        </>
        }
      </div>
    </main>
  );
}