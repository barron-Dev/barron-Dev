"use client";
import {useEffect,useState} from "react";
import type {FormEvent} from "react";

import {getCustomerOrganizations,apiFetch,type CustomerOrganization} from "../../lib/api";

const SERVICES=[["cybersecurity_assessment","Cybersecurity Assessment"],["dark_web_monitoring","Dark Web Monitoring"]];
const SERVICE_GUIDANCE:Record<string,{prompt:string;label:string;placeholder:string;help:string}>={
 cybersecurity_assessment:{prompt:"Identify the system, environment or business area you want assessed.",label:"System / environment",placeholder:"Website, application, cloud environment, network or business system",help:"Tell Cyclothone what is in scope and what you want the assessment to establish."},
 incident_response:{prompt:"Identify the incident or affected system and tell us what happened.",label:"Incident / affected system",placeholder:"Incident, domain, application, endpoint, account or affected system",help:"Add the known symptoms, timeframe and business impact below."},
 threat_intelligence:{prompt:"Give Cyclothone the indicator or threat context you want analyzed.",label:"Indicator / target",placeholder:"Domain, IP, hash, URL, email, actor or campaign",help:"Add the exact indicator where possible."},
 dark_web_monitoring:{prompt:"Choose the exact exposure you want Cyclothone to monitor.",label:"Target to monitor",placeholder:"example.com, brand name, email address, username or other approved target",help:"For a domain, enter the domain itself. For a brand, enter the exact brand name. Add multiple approved targets separated by commas."},
 brand_protection:{prompt:"Tell Cyclothone which brand or digital property you want protected.",label:"Brand / domain",placeholder:"Brand name or example.com",help:"Use the exact public brand name and/or domain you want monitored."},
 soc_mdr:{prompt:"Identify the environment Cyclothone should monitor and protect.",label:"Environment / system",placeholder:"Cloud, network, endpoint estate, application or other environment",help:"Add monitoring expectations, systems in scope and escalation requirements below."},
 ai_security:{prompt:"Identify the AI system, model or application that needs security review.",label:"AI system / model",placeholder:"AI application, model, agent, API or deployment",help:"Add the security objective, environment and known concerns below."},
 physical_security:{prompt:"Identify the authorized site or physical area that needs monitoring.",label:"Site / facility",placeholder:"Building, facility, site or authorized location",help:"Only submit locations you are authorized to monitor."},
 compliance:{prompt:"Identify the framework and the evidence or compliance outcome you need.",label:"Framework / objective",placeholder:"ISO 27001, SOC 2, PCI DSS, UAE PDPL, HIPAA…",help:"Add the scope, controls, audit date or evidence requirement below."},
 mobile_digital_intelligence:{prompt:"Identify the authorized mobile, device or digital target.",label:"Device / app / digital target",placeholder:"Device, application, account, domain or approved digital target",help:"Use an exact identifier where available and explain the objective below."}
};
const DEFAULT_GUIDANCE={prompt:"Describe the outcome you need Cyclothone to secure, investigate, monitor or assess.",label:"Target / scope",placeholder:"What should Cyclothone work on?",help:"Be specific about the target, scope and desired outcome."};
const REQUEST_SUGGESTIONS=[
 "Check public exposure",
 "Look for exposed email addresses",
 "Look for credential-pattern indicators",
 "Look for cryptocurrency wallet indicators",
 "Check the HTTP response and content type",
 "Give me a concise risk summary and next steps"
];

function Progress({value}:{value:number|null}){if(value===null)return null;return <div className="mt-5"><div className="mb-2 flex justify-between text-[9px] uppercase tracking-[.15em] text-[#67848d]"><span>Live workflow progress</span><span className="text-[#c2f35a]">{value}%</span></div><div className="cyclo-battery"><span style={{width:Math.max(0,Math.min(100,value))+"%"}}/></div></div>}

export default function RequestService(){ const [orgs,setOrgs]=useState<CustomerOrganization[]>([]),[org,setOrg]=useState(""),[service,setService]=useState("cybersecurity_assessment"),[urgency,setUrgency]=useState("normal"),[target,setTarget]=useState(""),[targetType,setTargetType]=useState("domain"),[description,setDescription]=useState(""),[verification,setVerification]=useState<any[]>([]),[error,setError]=useState<string|null>(null),[result,setResult]=useState<any>(null),[loading,setLoading]=useState(true);
 async function load(){setLoading(true);setError(null);try{const r=await getCustomerOrganizations();setOrgs(r.organizations);setOrg(r.organizations[0]?.id||"")}catch(e){setError(e instanceof Error?e.message:"Unable to load account")}finally{setLoading(false)}}
 useEffect(()=>{const requested=new URLSearchParams(window.location.search).get("service");if(requested&&SERVICES.some(x=>x[0]===requested))setService(requested);void load()},[]);
 async function submit(e:FormEvent){e.preventDefault();setError(null);setResult(null);try{const r=await apiFetch<any>("/api/v1/customer/service-requests",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({...(org?{organization_id:org}:{}),service_key:service,urgency,target:target.trim(),target_type:service==="dark_web_monitoring"?targetType:"url",description:[`Target: ${target.trim()}`,`Service objective: ${description.trim()}`].join("\n")})});setResult({...r,service});setTarget("");setDescription("")}catch(e){setError(e instanceof Error?e.message:"Service request failed")}}
 const current=orgs.find(x=>x.id===org); const guidance=SERVICE_GUIDANCE[service]||DEFAULT_GUIDANCE; const serviceName=SERVICES.find(x=>x[0]===service)?.[1]||service;
 const progress=typeof result?.progress_percent==="number"?result.progress_percent:typeof result?.progress==="number"?result.progress:null;
 const stage=typeof result?.stage==="string"?result.stage:null;
 return <main className="cyclo-water min-h-screen overflow-hidden text-[#e8f1f3]">
  <header className="relative z-10 flex items-center justify-between border-b border-white/10 bg-[#02090e]/70 px-5 py-4 backdrop-blur-2xl"><div className="flex items-center gap-3"><a href="/customer/services" className="cyclo-mark text-lg font-bold">◌</a><a href="/customer/services" className="font-semibold tracking-tight">CYCLOTHONE</a></div><a href="/customer/services" className="cyclo-pill px-3 py-2 text-[10px] text-[#9ab0b6]">Back to services</a></header>
  <div className="relative z-10 mx-auto max-w-4xl px-5 py-10 md:py-14">
   <div className="text-[9px] uppercase tracking-[.22em] text-[#4f8494]">Controlled request</div><h1 className="mt-3 text-3xl font-semibold md:text-4xl">Start a security workflow.</h1><p className="mt-3 text-sm leading-7 text-[#8ca6ad]">Tell Cyclothone what you want checked. Choose a suggestion below or describe your own objective.</p>
   {error&&<div className="mt-6 rounded-2xl border border-[#ff3d67]/30 bg-[#250910]/50 p-4 text-xs text-[#ff8ba0]">{error}</div>}
   {loading?<div className="mt-8 text-center text-xs text-[#69858d]">Reading account state…</div>:<form onSubmit={submit} className="mt-8">
    <div className="border-b border-white/10 pb-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-[9px] uppercase tracking-[.18em] text-[#4f8494]">Workspace</div>
          <div className="mt-1 text-sm">{current?.legal_name||"Personal request"}</div>
        </div>
        
      </div>
    </div>

    <section className="border-b border-white/10 py-7">
      <label className="block text-xs font-medium">1. Service
        <select value={service} onChange={e=>setService(e.target.value)} className="mt-3 w-full border-b border-white/15 bg-transparent py-3 text-base outline-none focus:border-[#c2f35a]/50">
          {SERVICES.map(x=><option key={x[0]} value={x[0]}>{x[1]}{x[0]==="dark_web_monitoring"?" — Limited coverage (1 of 5 sources live)":""}</option>)}
        </select>
      </label>
      <p className="mt-2 text-[11px] leading-5 text-[#78939a]">{guidance.prompt} {guidance.help}</p>
    </section>

    <section className="border-b border-white/10 py-7">
      <label className="block text-xs font-medium">2. Target
        <input required minLength={2} maxLength={2000} value={target} onChange={e=>setTarget(e.target.value)} className="mt-3 w-full border-b border-white/15 bg-transparent py-3 text-base outline-none focus:border-[#c2f35a]/50" placeholder={guidance.placeholder}/>
      </label>
      {service==="dark_web_monitoring"&&<select aria-label="Target type" value={targetType} onChange={e=>setTargetType(e.target.value)} className="mt-4 w-full border-b border-white/15 bg-transparent py-3 text-sm outline-none focus:border-[#c2f35a]/50"><option value="domain">Domain</option><option value="brand">Brand</option><option value="email">Email address</option><option value="username">Username</option><option value="ip">Public IP address</option><option value="url">URL</option><option value="other">Other approved target</option></select>}<p className="mt-2 text-[11px] leading-5 text-[#78939a]">{service==="dark_web_monitoring"?"Limited coverage: 1 of 5 sources currently live. Results will list checked and unavailable sources.":"Enter the website or system you want checked."}</p>
    </section>

    <section className="border-b border-white/10 py-7">
      <label className="block text-xs font-medium">3. What do you need?
        <textarea required minLength={10} maxLength={10000} value={description} onChange={e=>setDescription(e.target.value)} rows={5} className="mt-3 w-full resize-y border-b border-white/15 bg-transparent py-3 text-sm leading-6 outline-none focus:border-[#c2f35a]/50" placeholder="Choose a suggestion or tell Cyclothone what you want to find out."/>
      <div className="mt-4 flex flex-wrap gap-2">{(service==="dark_web_monitoring"?DARK_WEB_SUGGESTIONS:REQUEST_SUGGESTIONS).map(s=><button type="button" key={s} onClick={()=>setDescription(s)} className="rounded-full border border-white/10 bg-white/[0.035] px-3 py-2 text-[10px] text-[#a9bdc2] transition hover:border-[#c2f35a]/35 hover:bg-white/[0.07] hover:text-[#e8f1f3]">{s}</button>)}</div>
      </label>
    </section>

    <section className="flex flex-wrap items-center justify-between gap-5 py-6">
      <label className="text-xs">Priority
        <select value={urgency} onChange={e=>setUrgency(e.target.value)} className="ml-3 border-b border-white/15 bg-transparent px-2 py-2 text-xs outline-none focus:border-[#c2f35a]/50">
          {["low","normal","high","critical"].map(x=><option key={x}>{x}</option>)}
        </select>
      </label>
      <button disabled={loading} className="rounded-full border border-[#c2f35a]/50 bg-[#5f8e1f]/30 px-7 py-3.5 text-sm text-[#ddff9a] shadow-[0_14px_45px_rgba(194,243,90,.08)] transition hover:bg-[#6e9e25]/35 disabled:cursor-not-allowed disabled:opacity-35">
        Begin controlled workflow →
      </button>
    </section>

    {result&&<div className="border-t border-[#c2f35a]/20 py-6">
      <div className="text-[9px] uppercase tracking-[.18em] text-[#c2f35a]">Request accepted</div>
      <div className="mt-2 text-lg">The workflow has been recorded.</div>
      {stage&&<div className="mt-2 text-xs text-[#8ca6ad]">Live stage: <span className="text-[#c2f35a]">{stage}</span></div>}
      <Progress value={progress}/>
      {result?.result&&<div className="mt-6 rounded-[1.5rem] border border-white/10 bg-[#06181e]/70 p-5">
        <div className="text-[9px] uppercase tracking-[.18em] text-[#4f8494]">Real assessment result</div>
        <div className="mt-2 text-base">{result.result.target}</div>
        <div className="mt-4 grid grid-cols-2 gap-3 text-xs md:grid-cols-4">
          <div><span className="text-[#67848d]">HTTP</span><div className="mt-1 text-sm">{result.result.status_code}</div></div>
          <div><span className="text-[#67848d]">Findings</span><div className="mt-1 text-sm">{result.result.finding_count}</div></div>
          <div><span className="text-[#67848d]">Emails</span><div className="mt-1 text-sm">{result.result.observed_emails}</div></div>
          <div><span className="text-[#67848d]">Credential indicators</span><div className="mt-1 text-sm">{result.result.credential_indicators}</div></div>
        </div>
        <div className="mt-5 space-y-2">
          {result.result.findings?.map((finding:any,i:number)=><div key={i} className="rounded-xl border border-white/8 px-3 py-3 text-xs"><span className="uppercase text-[#c2f35a]">{finding.severity}</span><span className="ml-3">{finding.title}</span></div>)}
        </div>
        <div className="mt-4 text-[10px] text-[#67848d]">Evidence hash: {result.result.findings ? "captured with the assessment record" : "captured"}</div>
      </div>}
    </div>}
   </form>}
  </div>
 </main>
}