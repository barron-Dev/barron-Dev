"use client";

import { useEffect, useMemo, useState } from "react";
import { getCustomerCases, getCustomerOrganizations, getCustomerServiceRequests, setApiToken, type CustomerCase, type CustomerOrganization, type CustomerServiceRequest } from "../../../lib/api";

type Service={key:string;name:string;description:string;outcome:string;accent:string};
const SERVICES:Service[]=[
  ["cybersecurity_assessment","Cybersecurity Assessment","Check a website for real security exposure and surface-level weaknesses.","A live assessment with findings, evidence and clear next steps.","#5ccbc3"],
  ["dark_web_monitoring","Dark Web Monitoring","Monitor a domain for real exposure signals from configured external sources.","A live monitoring result with persisted findings, alerts and evidence.","#c2f35a"]
].map(([key,name,description,outcome,accent])=>({key,name,description,outcome,accent})) as Service[];

const statusTone:Record<string,string>={approved:"text-[#9ff5c0]",resolved:"text-[#9ff5c0]",closed:"text-[#9ff5c0]",pending:"text-[#ffd27a]",submitted:"text-[#ffd27a]",in_progress:"text-[#ffd27a]",rejected:"text-[#ff7c93]"};

export default function CustomerServices(){
 const [orgs,setOrgs]=useState<CustomerOrganization[]>([]),[requests,setRequests]=useState<CustomerServiceRequest[]>([]),[cases,setCases]=useState<CustomerCase[]>([]),[loading,setLoading]=useState(true),[error,setError]=useState("");
 async function load(){setLoading(true);setError("");try{const[o,r,c]=await Promise.all([getCustomerOrganizations(),getCustomerServiceRequests(),getCustomerCases()]);setOrgs(o.organizations);setRequests(r.service_requests);setCases(c.cases)}catch(e){setError(e instanceof Error?e.message:"Unable to load services")}finally{setLoading(false)}}
 useEffect(()=>{setApiToken(sessionStorage.getItem("cyclothone_access_token")||"");void load()},[]);
 const org=orgs[0]??null;
 const requestCount=useMemo(()=>requests.filter(r=>r.service_key==="cybersecurity_assessment").length,[requests]);
 const caseCount=useMemo(()=>cases.filter(c=>c.service_request?.service_key==="cybersecurity_assessment").length,[cases]);
 const latest=requests.filter(r=>r.service_key==="cybersecurity_assessment").sort((a,b)=>String(b.created_at).localeCompare(String(a.created_at)))[0];
 return <main className="cyclo-water min-h-screen overflow-hidden text-[#e8f1f3]">
  <header className="relative z-10 flex flex-wrap items-center justify-between gap-4 border-b border-white/10 bg-[#02090e]/70 px-5 py-4 backdrop-blur-2xl">
   <div className="flex items-center gap-3"><a href="/customer/overview" className="cyclo-mark text-lg font-bold">◌</a><div><a href="/customer/overview" className="font-semibold tracking-tight">CYCLOTHONE</a><span className="ml-3 text-[9px] uppercase tracking-[.18em] text-[#789aa4]">Customer</span></div></div>
   <nav className="flex flex-wrap gap-2 text-[10px]"><a href="/customer/overview" className="cyclo-pill px-3 py-2 text-[#9ab0b6]">Overview</a><a href="/customer/services" className="cyclo-pill px-3 py-2 text-[#c2f35a]">Services</a><a href="/customer/cases" className="cyclo-pill px-3 py-2 text-[#9ab0b6]">Cases</a><a href="/customer/profile" className="cyclo-pill px-3 py-2 text-[#9ab0b6]">Profile</a></nav>
  </header>
  <div className="relative z-10 mx-auto max-w-6xl px-5 py-10 md:px-8">
   <div className="max-w-3xl"><div className="text-[9px] uppercase tracking-[.22em] text-[#4f8494]">Discover. Understand. Protect.</div><h1 className="mt-3 text-3xl font-semibold tracking-tight md:text-5xl">Start with what you need checked.</h1><p className="mt-4 text-sm leading-7 text-[#9ab0b6]">Choose a service that is genuinely available today. Cyclothone will show you what it checked, what it found, and the evidence behind the result.</p></div>
   {error&&<div className="mt-7 rounded-2xl border border-[#ff3d67]/30 bg-[#250910]/50 p-4 text-xs text-[#ff8ba0]">{error}</div>}
   {!loading&&<div className="mt-8 flex flex-wrap items-center justify-between gap-3 text-xs"><span className="text-[#69858d]">{SERVICES.length} services available now</span>{org&&<span className="cyclo-pill px-4 py-2 text-[10px] text-[#9ff5c0]">{org.legal_name}</span>}</div>}
   {loading?<div className="mt-8 p-10 text-center text-xs text-[#69858d]">Loading available services…</div>:<div className="mt-7 max-w-3xl">
    <a href="/customer/services/cybersecurity_assessment" className="group relative block overflow-hidden rounded-[2rem] border border-white/[0.12] bg-white/[0.045] px-7 py-8 shadow-[0_20px_70px_rgba(0,0,0,.18)] backdrop-blur-xl transition-all duration-300 hover:-translate-y-0.5 hover:border-white/20 hover:bg-white/[0.065]">
     <div className="absolute -right-16 -top-16 h-40 w-40 rounded-full bg-[#5ccbc3]/[0.08] blur-3xl"/><div className="relative z-10 flex items-start justify-between gap-5"><div><div className="font-mono text-[9px] text-[#4e707b]">AVAILABLE NOW</div><h2 className="mt-2 text-2xl font-medium">{SERVICES[0].name}</h2></div>{latest&&<span className={"text-[9px] uppercase tracking-wider "+(statusTone[latest.status]??"text-[#789aa4]")}>{latest.status.replaceAll("_"," ")}</span>}</div>
     <p className="relative z-10 mt-5 max-w-2xl text-sm leading-7 text-[#9ab0b6]">{SERVICES[0].description}</p>
     <div className="relative z-10 mt-6 border-t border-white/10 pt-5"><div className="text-[9px] uppercase tracking-[.16em] text-[#4e707b]">What you receive</div><p className="mt-2 text-xs leading-6 text-[#9ab0b6]">{SERVICES[0].outcome}</p></div>
     <div className="relative z-10 mt-6 flex items-center justify-between"><span className="text-[10px] text-[#59747d]">{requestCount} request{requestCount===1?"":"s"} · {caseCount} case{caseCount===1?"":"s"}</span><span className="flex h-10 w-10 items-center justify-center rounded-full border border-[#c2f35a]/25 bg-[#c2f35a]/[0.06] text-xl text-[#c2f35a] transition-transform group-hover:translate-x-1">→</span></div>
    </a>
   </div>}
  </div>
 </main>
}