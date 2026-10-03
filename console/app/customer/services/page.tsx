"use client";

import { useEffect, useMemo, useState } from "react";
import { getCustomerCases, getCustomerOrganizations, getCustomerServiceRequests, setApiToken, type CustomerCase, type CustomerOrganization, type CustomerServiceRequest } from "../../../lib/api";

type Service = {
  key: string;
  name: string;
  description: string;
  outcome: string;
};

const SERVICES: Service[] = [
  { key: "cybersecurity_assessment", name: "Cybersecurity Assessment", description: "Assess your organization's security posture and identify verified gaps.", outcome: "Assessment findings and customer-visible recommendations." },
  { key: "incident_response", name: "Incident Response", description: "Coordinate response to an active or suspected security incident.", outcome: "Case status, response activity and documented outcome." },
  { key: "threat_intelligence", name: "Threat Intelligence", description: "Monitor and investigate relevant indicators and threat information.", outcome: "Relevant intelligence findings and case updates." },
  { key: "web_intelligence", name: "Web Intelligence", description: "Monitor approved web targets for security-relevant findings.", outcome: "Verified findings and customer-visible status." },
  { key: "scam_monitoring", name: "Scam Monitoring", description: "Monitor approved scam-related exposure affecting your organization.", outcome: "Findings, status and response recommendations." },
  { key: "dark_web_monitoring", name: "Dark Web Monitoring", description: "Monitor approved sources for relevant exposure and findings.", outcome: "Verified findings and customer-visible case activity." },
  { key: "brand_protection", name: "Brand Protection", description: "Monitor brand assets and investigate suspected abuse or impersonation.", outcome: "Verified threats, status and response activity." },
  { key: "soc_mdr", name: "SOC / MDR", description: "Security operations monitoring and managed detection workflows.", outcome: "Security cases, activity and operational results." },
  { key: "ai_security", name: "AI Security", description: "Assess and monitor AI systems and AI-related security exposure.", outcome: "Verified findings, controls and customer-visible results." },
  { key: "physical_security", name: "Physical Security", description: "Monitor approved physical security assets and events.", outcome: "Verified physical findings and case activity." },
  { key: "compliance", name: "Compliance", description: "Assess approved compliance frameworks and supporting evidence.", outcome: "Assessment status, evidence and assurance results." },
  { key: "hunting", name: "Threat Hunting", description: "Run approved hunts against your authorized security scope.", outcome: "Hunt status, findings and resulting cases." },
  { key: "investigation", name: "Investigation", description: "Conduct an authorized investigation with evidence and activity tracking.", outcome: "Investigation status, evidence and documented outcome." },
  { key: "recovery", name: "Recovery", description: "Use the approved recovery workflow for protected organizational data.", outcome: "Recovery status, verification and documented result." },
  { key: "mobile_digital_intelligence", name: "Mobile & Digital Intelligence", description: "Authorized mobile, device, network and location intelligence for security investigations.", outcome: "Verified provider observations, investigation evidence and controlled response." },
];

const statusTone: Record<string,string> = {
  approved:"border-[#00e07a]/40 bg-[#00e07a]/10 text-[#7df0ad]",
  resolved:"border-[#00e07a]/40 bg-[#00e07a]/10 text-[#7df0ad]",
  closed:"border-[#00e07a]/40 bg-[#00e07a]/10 text-[#7df0ad]",
  pending:"border-[#ffb020]/40 bg-[#ffb020]/10 text-[#ffd27a]",
  submitted:"border-[#ffb020]/40 bg-[#ffb020]/10 text-[#ffd27a]",
  in_progress:"border-[#ffb020]/40 bg-[#ffb020]/10 text-[#ffd27a]",
  rejected:"border-[#ff2d55]/40 bg-[#ff2d55]/10 text-[#ff6b83]",
};

export default function CustomerServices() {
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
      setError(e instanceof Error ? e.message : "Unable to load customer services");
    } finally { setLoading(false); }
  }

  useEffect(() => {
    setApiToken(sessionStorage.getItem("cyclothone_access_token") || "");
    void load();
  }, []);

  const org = orgs[0] ?? null;
  const requestCounts = useMemo(() => {
    const map: Record<string,number> = {};
    for (const r of requests) map[r.service_key] = (map[r.service_key] ?? 0) + 1;
    return map;
  }, [requests]);
  const caseCounts = useMemo(() => {
    const map: Record<string,number> = {};
    for (const c of cases) {
      const key = c.service_request?.service_key;
      if (key) map[key] = (map[key] ?? 0) + 1;
    }
    return map;
  }, [cases]);

  return <main className="relative min-h-screen overflow-hidden bg-[#021014] text-[#e8eef6]">
    <header className="relative z-10 flex min-h-14 flex-wrap items-center justify-between gap-3 border-b border-white/10 bg-[#06181e]/70 px-5 py-3 backdrop-blur-2xl">
      <div><a href="/customer/overview" className="font-semibold">Cyclothone</a><span className="ml-3 text-[10px] uppercase tracking-[.16em] text-[#70d3ca]">Customer services</span></div>
      <nav className="flex flex-wrap gap-2 text-[10px]">
        <a href="/customer/overview" className="border border-white/10 px-3 py-2">Overview</a>
        <a href="/customer/workspace" className="border border-white/10 px-3 py-2">Workspace</a>
        <a href="/customer/cases" className="border border-white/10 px-3 py-2">Cases</a>
        <a href="/customer/profile" className="border border-white/10 px-3 py-2">Profile</a>
      </nav>
    </header>

    <div className="relative z-10 mx-auto max-w-7xl px-5 py-8 md:px-8">
      <div className="max-w-4xl">
        <div className="text-[10px] uppercase tracking-[.18em] text-[#688487]">Cyclothone security portfolio</div>
        <h1 className="mt-2 text-3xl font-semibold md:text-4xl">Security services, in one place.</h1>
        <p className="mt-3 max-w-3xl text-sm leading-6 text-[#91aaab]">Explore what Cyclothone can monitor, investigate, assess, protect, and recover. Start with the service you need; organization setup is only required when you are ready to submit a protected request.</p>
      </div>

      {error && <div className="mt-6 border border-[#ff2d55]/40 bg-[#ff2d55]/5 p-4 text-xs text-[#ff6b83]">{error}</div>}

      {loading ? <div className="mt-8 border border-white/10 bg-[#06181e]/70 p-8 text-center text-xs text-[#688487]">Loading service status…</div> :
      <div className="mt-8">
        <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
          <div><div className="text-sm font-medium">The Cyclothone portfolio</div><div className="mt-1 text-xs text-[#688487]">{SERVICES.length} security capabilities available to explore</div></div>
          {!org ? <a href="/customer/profile" className="border border-white/10 px-4 py-2 text-[10px] text-[#91aaab]">Set up organization when ready →</a> :
          <div className="border border-[#00e07a]/20 bg-[#00e07a]/5 px-4 py-2 text-[10px] text-[#7df0ad]">{org.legal_name} · workspace {org.admission_status}</div>}
        </div>

        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {SERVICES.map((service,index) => {
            const count = requestCounts[service.key] ?? 0;
            const serviceCases = caseCounts[service.key] ?? 0;
            const latest = requests.filter(r => r.service_key === service.key).sort((a,b) => String(b.created_at).localeCompare(String(a.created_at)))[0];
            return <article key={service.key} className="group flex min-h-[275px] flex-col rounded-[2rem] border border-white/10 bg-[#06181e]/65 p-5 shadow-[0_24px_80px_rgba(0,0,0,.24)] backdrop-blur-xl transition hover:-translate-y-1 hover:border-[#4fc4bd]/30">
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-3"><span className="font-mono text-[10px] text-[#4f7779]">{String(index+1).padStart(2,"0")}</span><h2 className="font-medium">{service.name}</h2></div>
                {latest && <span className={"rounded border px-2 py-1 text-[9px] "+(statusTone[latest.status] ?? "border-white/10 text-[#91aaab]")}>{latest.status.replaceAll("_"," ")}</span>}
              </div>
              <p className="mt-4 text-xs leading-5 text-[#91aaab]">{service.description}</p>
              <div className="mt-4 rounded-2xl border border-white/10 bg-black/10 p-3">
                <div className="text-[9px] uppercase tracking-[.12em] text-[#688487]">What you receive</div>
                <div className="mt-1 text-[11px] leading-5 text-[#c7d8d6]">{service.outcome}</div>
              </div>
              <div className="mt-auto flex items-center justify-between gap-3 pt-5">
                <div className="text-[10px] text-[#688487]">{org ? `${count} request${count===1?"":"s"} · ${serviceCases} case${serviceCases===1?"":"s"}` : "Explore service details"}</div>
                <a href={"/customer/services/"+encodeURIComponent(service.key)} className="border border-[#5ccbc3] px-3 py-2 text-[10px] text-[#5ccbc3]">Explore →</a>
              </div>
            </article>;
          })}
        </div>
      </div>}
    </div>
  </main>;
}
