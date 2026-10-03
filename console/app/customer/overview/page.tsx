"use client";

import { useEffect, useState } from "react";
import { AuthActions } from "@/components/AuthActions";
import { getCustomerCases, getCustomerOrganizations, getCustomerServiceRequests, type CustomerCase, type CustomerOrganization, type CustomerServiceRequest } from "../../../lib/api";

const SERVICES = [
  ["cybersecurity_assessment","Cybersecurity Assessment","Assess exposure, controls and security posture.","Verified findings and remediation guidance."],
  ["incident_response","Incident Response","Coordinate an active or suspected security incident.","Case activity and documented outcome."],
  ["threat_intelligence","Threat Intelligence","Understand relevant threats, indicators and campaigns.","Verified intelligence and investigation pivots."],
  ["web_intelligence","Web Intelligence","Monitor approved web targets for relevant activity.","Verified web findings and status."],
  ["scam_monitoring","Scam Monitoring","Identify scam signals affecting people, brands or channels.","Verified signals and response recommendations."],
  ["dark_web_monitoring","Dark Web Monitoring","Monitor approved sources for organizational exposure.","Verified exposure and case activity."],
  ["brand_protection","Brand Protection","Detect impersonation, abuse and threats to brand assets.","Verified threats and response activity."],
  ["soc_mdr","SOC / MDR","Operate continuous security monitoring and detection workflows.","Security cases and operational results."],
  ["ai_security","AI Security","Assess and monitor AI systems and AI-related exposure.","Governed findings, controls and results."],
  ["physical_security","Physical Security","Monitor authorized physical and location security signals.","Verified physical findings and case activity."],
  ["compliance","Compliance","Measure security controls against required frameworks.","Assurance status, evidence and findings."],
  ["hunting","Threat Hunting","Test authorized hypotheses beyond existing alerts.","Hunt status, findings and resulting cases."],
  ["investigation","Investigation","Connect authorized evidence into a defensible investigation.","Evidence and documented outcome."],
  ["recovery","Recovery","Restore trusted operation through the approved recovery workflow.","Recovery status and verified result."],
  ["mobile_digital_intelligence","Mobile & Digital Intelligence","Authorized mobile, device, network, location and RF intelligence.","Verified provider observations and controlled investigation."]
] as const;

const tone: Record<string,string>={approved:"text-[#7df0ad]",verified:"text-[#7df0ad]",pending:"text-[#ffd27a]",submitted:"text-[#ffd27a]",in_progress:"text-[#ffd27a]",resolved:"text-[#7df0ad]",closed:"text-[#7df0ad]",rejected:"text-[#ff6b83]"};

export default function CustomerOverview(){
 const [orgs,setOrgs]=useState<CustomerOrganization[]>([]),[requests,setRequests]=useState<CustomerServiceRequest[]>([]),[cases,setCases]=useState<CustomerCase[]>([]),[loading,setLoading]=useState(true),[error,setError]=useState("");
 useEffect(()=>{void (async()=>{try{const[o,r,c]=await Promise.all([getCustomerOrganizations(),getCustomerServiceRequests(),getCustomerCases()]);setOrgs(o.organizations);setRequests(r.service_requests);setCases(c.cases)}catch(e){setError(e instanceof Error?e.message:"Unable to load your account")}finally{setLoading(false)}})()},[]);
 const org=orgs[0]??null;
 return <main className="min-h-screen bg-[#05070a] text-[#e8eef6]">
  <header className="flex min-h-14 flex-wrap items-center justify-between gap-3 border-b border-[#1a2330] bg-[#0a0e14] px-5 py-3">
   <div><a href="/" className="font-semibold">Cyclothone</a><span className="ml-3 text-[10px] uppercase tracking-[.16em] text-[#00d9ff]">Customer</span></div>
   <nav className="flex flex-wrap gap-2 text-[10px]"><a href="/customer/services" className="border border-[#00d9ff] px-3 py-2 text-[#00d9ff]">Services</a><a href="/customer/cases" className="border border-[#2a3646] px-3 py-2">Cases</a><a href="/customer/profile" className="border border-[#2a3646] px-3 py-2">Profile</a><AuthActions/></nav>
  </header>
  <div className="mx-auto max-w-7xl px-5 py-9 md:px-8">
   <div className="max-w-4xl"><div className="text-[10px] uppercase tracking-[.18em] text-[#5a6675]">Customer command center</div><h1 className="mt-2 text-3xl font-semibold">{org?org.legal_name:"Welcome to Cyclothone"}</h1><p className="mt-3 text-sm leading-6 text-[#8a97a8]">Explore Cyclothone's security capabilities first. Authentication is complete; an organization is requested only when the service you choose needs an organizational security boundary.</p></div>
   {error&&<div className="mt-6 border border-[#ff2d55]/40 bg-[#ff2d55]/5 p-4 text-xs text-[#ff6b83]">{error}</div>}
   {loading?<div className="mt-8 border border-[#1a2330] bg-[#0a0e14] p-8 text-center text-xs text-[#5a6675]">Loading your customer workspace…</div>:<>
    {!org&&<div className="mt-6 border border-[#00d9ff]/20 bg-[#00d9ff]/5 p-5"><div className="text-[10px] uppercase tracking-[.16em] text-[#00d9ff]">No organization yet</div><p className="mt-2 text-xs leading-5 text-[#8a97a8]">You can browse every service and its details without creating an organization. Create one only when you're ready to request a protected service.</p></div>}
    {org&&<div className="mt-8 grid gap-px bg-[#1a2330] md:grid-cols-3">{[["Organization",org.admission_status||"pending","Admission status"],["Service requests",String(requests.length),requests.length+" total"],["Security cases",String(cases.length),cases.length+" total"]].map(([a,b,c])=><div key={a} className="bg-[#0a0e14] p-5"><div className="text-[10px] uppercase tracking-[.12em] text-[#5a6675]">{a}</div><div className={"mt-3 text-xl font-medium "+(a==="Organization"?(tone[b]??""):"")}>{b}</div><div className="mt-1 text-[10px] text-[#8a97a8]">{c}</div></div>)}</div>}
    <section className="mt-8"><div className="flex flex-wrap items-end justify-between gap-3"><div><div className="text-[10px] uppercase tracking-[.16em] text-[#00d9ff]">Full service portfolio</div><h2 className="mt-2 text-2xl font-semibold">Security services</h2><p className="mt-2 text-xs text-[#8a97a8]">Understand the service, expected outcome and live status before requesting anything.</p></div><a href="/customer/services" className="border border-[#2a3646] px-4 py-2 text-[10px]">View full catalog →</a></div>
     <div className="mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-3">{SERVICES.map(([key,name,desc,outcome])=><a key={key} href={"/customer/services/"+encodeURIComponent(key)} className="group min-h-[190px] border border-[#1a2330] bg-[#0a0e14] p-5 transition hover:border-[#00d9ff]/50"><div className="flex items-start justify-between gap-3"><h3 className="font-medium">{name}</h3><span className="text-[#00d9ff]">→</span></div><p className="mt-3 text-xs leading-5 text-[#8a97a8]">{desc}</p><div className="mt-4 border-t border-[#1a2330] pt-3 text-[10px] text-[#5a6675]"><span className="uppercase tracking-[.1em]">Outcome</span><div className="mt-1 text-[#b9c7d5]">{outcome}</div></div></a>)}</div>
    </section>
    {org&&<section className="mt-8 border border-[#1a2330] bg-[#0a0e14] p-5"><div className="flex items-center justify-between"><h2 className="font-medium">Recent requests</h2><a href="/request-service" className="text-[10px] text-[#00d9ff]">New request →</a></div>{!requests.length?<p className="mt-4 text-xs text-[#5a6675]">No requests yet.</p>:<div className="mt-3 divide-y divide-[#1a2330]">{requests.slice(0,5).map(r=><div key={r.id} className="flex justify-between gap-3 py-3 text-xs"><span>{r.service_key}</span><span className={tone[r.status]??"text-[#8a97a8]"}>{r.status}</span></div>)}</div>}</section>}
   </>}
  </div>
 </main>
}