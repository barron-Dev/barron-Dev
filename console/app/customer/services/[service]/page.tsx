"use client";

import { useEffect, useMemo, useState } from "react";
import { useParams } from "next/navigation";
import { getCustomerCases, getCustomerOrganizations, getCustomerServiceRequests, setApiToken, type CustomerCase, type CustomerOrganization, type CustomerServiceRequest } from "../../../../lib/api";

const SERVICES: Record<string,{name:string;description:string;outcome:string}> = {
  cybersecurity_assessment:{name:"Cybersecurity Assessment",description:"Assess your organization's security posture and identify verified gaps.",outcome:"Assessment findings and customer-visible recommendations."},
  incident_response:{name:"Incident Response",description:"Coordinate response to an active or suspected security incident.",outcome:"Case status, response activity and documented outcome."},
  threat_intelligence:{name:"Threat Intelligence",description:"Monitor and investigate relevant indicators and threat information.",outcome:"Relevant intelligence findings and case updates."},
  web_intelligence:{name:"Web Intelligence",description:"Monitor approved web targets for security-relevant findings.",outcome:"Verified findings and customer-visible status."},
  scam_monitoring:{name:"Scam Monitoring",description:"Monitor approved scam-related exposure affecting your organization.",outcome:"Findings, status and response recommendations."},
  dark_web_monitoring:{name:"Dark Web Monitoring",description:"Monitor approved sources for relevant exposure and findings.",outcome:"Verified findings and customer-visible case activity."},
  brand_protection:{name:"Brand Protection",description:"Monitor brand assets and investigate suspected abuse or impersonation.",outcome:"Verified threats, status and response activity."},
  soc_mdr:{name:"SOC / MDR",description:"Security operations monitoring and managed detection workflows.",outcome:"Security cases, activity and operational results."},
  ai_security:{name:"AI Security",description:"Assess and monitor AI systems and AI-related security exposure.",outcome:"Verified findings, controls and customer-visible results."},
  physical_security:{name:"Physical Security",description:"Monitor approved physical security assets and events.",outcome:"Verified physical findings and case activity."},
  compliance:{name:"Compliance",description:"Assess approved compliance frameworks and supporting evidence.",outcome:"Assessment status, evidence and assurance results."},
  hunting:{name:"Threat Hunting",description:"Run approved hunts against your authorized security scope.",outcome:"Hunt status, findings and resulting cases."},
  investigation:{name:"Investigation",description:"Conduct an authorized investigation with evidence and activity tracking.",outcome:"Investigation status, evidence and documented outcome."},
  recovery:{name:"Recovery",description:"Use the approved recovery workflow for protected organizational data.",outcome:"Recovery status, verification and documented result."},
};

const tone=(s:string)=>["resolved","closed","approved"].includes(s)?"text-[#7df0ad] border-[#00e07a]/40":["rejected"].includes(s)?"text-[#ff6b83] border-[#ff2d55]/40":"text-[#ffd27a] border-[#ffb020]/40";

export default function CustomerServiceDetail(){
  const params=useParams<{service:string}>(); const serviceKey=String(params.service||""); const service=SERVICES[serviceKey];
  const [orgs,setOrgs]=useState<CustomerOrganization[]>([]); const [requests,setRequests]=useState<CustomerServiceRequest[]>([]); const [cases,setCases]=useState<CustomerCase[]>([]);
  const [loading,setLoading]=useState(true); const [error,setError]=useState("");

  useEffect(()=>{setApiToken(sessionStorage.getItem("cyclothone_access_token")||""); void load()},[]);
  async function load(){setLoading(true);setError("");try{const [o,r,c]=await Promise.all([getCustomerOrganizations(),getCustomerServiceRequests(),getCustomerCases()]);setOrgs(o.organizations);setRequests(r.service_requests);setCases(c.cases)}catch(e){setError(e instanceof Error?e.message:"Unable to load service status")}finally{setLoading(false)}}
  const serviceRequests=useMemo(()=>requests.filter(r=>r.service_key===serviceKey),[requests,serviceKey]);
  const serviceCases=useMemo(()=>cases.filter(c=>c.service_request?.service_key===serviceKey),[cases,serviceKey]);

  if(!service) return <main className="min-h-screen bg-[#05070a] p-6 text-[#e8eef6]"><div className="mx-auto max-w-3xl"><a href="/customer/services" className="text-xs text-[#00d9ff]">← Services</a><h1 className="mt-6 text-2xl font-semibold">Service not found</h1><p className="mt-2 text-xs text-[#8a97a8]">This service is not part of the customer catalog.</p></div></main>;

  return <main className="min-h-screen bg-[#05070a] text-[#e8eef6]">
    <header className="flex min-h-14 items-center justify-between border-b border-[#1a2330] bg-[#0a0e14] px-5">
      <div><a href="/customer/services" className="font-semibold">Cyclothone</a><span className="ml-3 text-[10px] uppercase tracking-[.16em] text-[#ffb347]">Customer service</span></div>
      <div className="flex gap-2"><a href="/customer/services" className="border border-[#2a3646] px-3 py-2 text-[10px]">All services</a><a href="/customer/cases" className="border border-[#2a3646] px-3 py-2 text-[10px]">Cases</a></div>
    </header>
    <div className="mx-auto max-w-5xl px-5 py-8">
      <a href="/customer/services" className="text-[10px] text-[#00d9ff]">← Customer services</a>
      <div className="mt-5 border border-[#1a2330] bg-[#0a0e14] p-6">
        <div className="text-[10px] uppercase tracking-[.16em] text-[#5a6675]">{orgs[0]?.legal_name||"Organization"}</div>
        <h1 className="mt-2 text-3xl font-semibold">{service.name}</h1>
        <p className="mt-3 max-w-2xl text-sm leading-6 text-[#8a97a8]">{service.description}</p>
        <div className="mt-5 border-t border-[#1a2330] pt-4"><div className="text-[9px] uppercase tracking-[.12em] text-[#5a6675]">Customer outcome</div><div className="mt-1 text-xs">{service.outcome}</div></div>
        <div className="mt-5 flex gap-2"><a href={"/request-service?service="+encodeURIComponent(serviceKey)} className="border border-[#00d9ff] px-4 py-2 text-[10px] text-[#00d9ff]">Request this service</a><button onClick={()=>void load()} className="border border-[#2a3646] px-4 py-2 text-[10px]">Refresh</button></div>
      </div>
      {error&&<div className="mt-5 border border-[#ff2d55]/40 p-3 text-xs text-[#ff6b83]">{error}</div>}
      {loading?<div className="mt-5 border border-[#1a2330] bg-[#0a0e14] p-6 text-xs text-[#5a6675]">Loading live service status…</div>:
      <div className="mt-5 grid gap-5 md:grid-cols-2">
        <section className="border border-[#1a2330] bg-[#0a0e14] p-5"><h2 className="text-xs font-medium">Your requests</h2>{serviceRequests.length?<div className="mt-3 space-y-2">{serviceRequests.map(r=><div key={r.id} className="border border-[#1a2330] p-3"><div className="flex justify-between gap-2 text-xs"><span>{r.urgency||"normal"} priority</span><span className={"rounded border px-2 py-0.5 text-[9px] "+tone(r.status)}>{r.status}</span></div><div className="mt-2 text-[9px] text-[#5a6675]">{new Date(r.created_at).toLocaleString()}</div></div>)}</div>:<div className="mt-5 text-xs text-[#5a6675]">No requests for this service yet.</div>}</section>
        <section className="border border-[#1a2330] bg-[#0a0e14] p-5"><h2 className="text-xs font-medium">Related security cases</h2>{serviceCases.length?<div className="mt-3 space-y-2">{serviceCases.map(c=><a href="/customer/cases" key={c.case_id} className="block border border-[#1a2330] p-3 hover:border-[#2a3646]"><div className="flex justify-between gap-2 text-xs"><span>{c.case.case_number}</span><span>{c.case.status}</span></div><div className="mt-2 text-xs">{c.case.title}</div><div className="mt-1 text-[9px] text-[#5a6675]">{c.case.severity}</div></a>)}</div>:<div className="mt-5 text-xs text-[#5a6675]">No customer-visible cases for this service.</div>}</section>
      </div>}
    </div>
  </main>;
}