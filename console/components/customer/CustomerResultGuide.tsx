"use client";

import React, { useState } from "react";
import { openCustomerCase } from "../../lib/api";

type AnyRecord = Record<string, any>;
type Props = { service: string; request: AnyRecord; result: AnyRecord };

const LABELS: Record<string, string> = {
  dark_web_monitoring: "Dark Web Monitoring",
  cybersecurity_assessment: "Cybersecurity Assessment",
  incident_response: "Incident Response",
  threat_intelligence: "Threat Intelligence",
  brand_protection: "Brand Protection",
  web_intelligence: "Web Intelligence",
  scam_monitoring: "Scam Monitoring",
  soc_mdr: "SOC / MDR",
  ai_security: "AI Security",
  compliance: "Compliance",
  hunting: "Threat Hunting",
  investigation: "Investigation",
  recovery: "Recovery",
};

function arr(value: unknown): AnyRecord[] {
  return Array.isArray(value) ? value.filter((x) => x && typeof x === "object") as AnyRecord[] : [];
}
function text(...values: unknown[]): string {
  for (const value of values) if (typeof value === "string" && value.trim()) return value.trim();
  return "";
}
function titleCase(value: string): string {
  return value.replace(/[_-]+/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}
function safeCount(value: unknown): string {
  return typeof value === "number" && Number.isFinite(value) ? value.toLocaleString() : "not recorded";
}
function exposureKind(item: AnyRecord): string {
  return text(item.indicator_type, item.exposure_type, item.category, item.kind, item.type, item.source_id, item.source, "security signal");
}
function severityOf(item: AnyRecord): string {
  return text(item.severity, item.risk_level, item.priority, "unrated").toLowerCase();
}
function actionPlan(kind: string, service: string, findings: AnyRecord[]): string[] {
  const haystack = (kind + " " + findings.map((f) => [f.title, f.summary, f.description, f.indicator_type, f.category, f.source_id].filter(Boolean).join(" ")).join(" ")).toLowerCase();
  const steps: string[] = [];
  if (/secret|api.?key|credential|password|token|private.?key/.test(haystack)) {
    steps.push("If the evidence contains a real credential or key, revoke it and issue a replacement now; do not merely delete the public copy. Check access logs for use.");
  }
  if (/email|identity|account|employee|customer|personal data|pii/.test(haystack)) {
    steps.push("Confirm which identity or data owner is affected, assess whether the information is still accessible, and follow your privacy and incident-notification process if exposure is substantiated.");
  }
  if (/brand|impersonat|social|telegram|bluesky|tiktok|youtube|phish|scam|domain/.test(haystack)) {
    steps.push("Verify the account, page, domain, or post from the evidence link. Preserve a timestamped copy, then report or request takedown through the platform or registrar when abuse is confirmed.");
  }
  if (/ransom|leak|paste|dark.?web|forum|marketplace|breach|dump/.test(haystack) || service === "dark_web_monitoring") {
    steps.push("Preserve the source URL, first-seen/last-seen times, matched asset, and evidence fingerprint. Check whether the same exposure appears in other sources and assign an owner to investigate.");
  }
  if (!steps.length && findings.length) {
    steps.push("Validate the evidence against the affected asset and source before taking disruptive action; record the owner, decision, and verification result in the case.");
  }
  if (findings.length) {
    steps.push("Assign an accountable owner and due time. Link the finding to an existing case or open one using the customer case workflow, then keep it open until remediation is verified.");
  } else {
    steps.push("No finding-specific remediation is indicated by this result. Review source coverage and the scan scope before deciding whether to close or rerun the workflow.");
  }
  return Array.from(new Set(steps)).slice(0, 4);
}

export function CustomerResultGuide({ service, request, result }: Props) {
  const [openingCase, setOpeningCase] = useState(false);
  const [caseMessage, setCaseMessage] = useState("");
  const [createdCaseId, setCreatedCaseId] = useState("");
  const findings = arr(result.findings);
  const alerts = arr(result.alerts);
  const checked = arr(result.sources_checked);
  const unavailable = arr(result.sources_unavailable);
  const corpus = result.historical_corpus && typeof result.historical_corpus === "object" ? result.historical_corpus as AnyRecord : null;
  const sourceCoverage = result.source_coverage && typeof result.source_coverage === "object" ? result.source_coverage as AnyRecord : null;
  const outcome = text(result.outcome, result.state, request.status, request.state, "result recorded").toLowerCase();
  const isDarkWeb = service === "dark_web_monitoring";
  const findingCount = Math.max(findings.length, typeof result.finding_count === "number" ? result.finding_count : 0);
  const alertCount = Math.max(alerts.length, typeof result.alert_count === "number" ? result.alert_count : 0);
  const scanned = corpus?.records_scanned;
  const exactMatches = corpus?.exact_matches;
  const isPartial = unavailable.length > 0 || /partial|source_unavailable|incomplete|failed/.test(outcome);
  const noEvidence = findingCount === 0 && alertCount === 0;
  // Rank both persisted findings and alerts so the headline cannot hide a more severe alert.
  const severity = [...findings, ...alerts].reduce((best, item) => {
    const s = severityOf(item);
    const rank = /critical/.test(s) ? 4 : /high/.test(s) ? 3 : /medium|moderate/.test(s) ? 2 : /low/.test(s) ? 1 : 0;
    return rank > best.rank ? { label: s, rank } : best;
  }, { label: "unrated", rank: 0 });
  const resultTitle = findingCount > 0
    ? `Cyclothone identified ${findingCount.toLocaleString()} ${findingCount === 1 ? "security signal" : "security signals"}`
    : isPartial
      ? "Cyclothone completed a partial check"
      : "No matching exposure was recorded in this run";
  const explanation = findingCount > 0
    ? `The workflow returned ${findingCount.toLocaleString()} finding(s) and ${alertCount.toLocaleString()} alert(s). These are signals that need evidence-led validation; a signal alone does not prove that an account was compromised or that a breach occurred.`
    : isPartial
      ? "Some sources or checks did not complete. This is an incomplete view, not a clean bill of health. The unavailable checks below define what Cyclothone could not assess."
      : "No findings were recorded in the available result. This means no matching signal was recorded within this run's scope and completed checks; it does not prove that the asset is risk-free or that every global source was searched.";
  const primaryKind = findings.length ? titleCase(exposureKind(findings[0])) : isDarkWeb ? "Public and dark-web exposure" : LABELS[service] ?? titleCase(service);
  const steps = actionPlan(primaryKind, service, findings);
  const caseId = text(createdCaseId, result.case_id, request.case_id);
  const state = titleCase(outcome);
  const evidenceLinks = Array.from(new Set(findings.map((f) => text(f.source_url, f.evidence_url, f.url)).filter((u) => /^https?:\/\//i.test(u)))).slice(0, 4);
  const remediationStatus = text(result.remediation_status, result.remediation?.status).toLowerCase();
  const remediationVerified = result.remediation_verified === true || remediationStatus === "verified";
  const stages = [
    { name: "Request identity", status: request.id ? "Recorded" : "Missing", detail: request.id ? "This result is attached to a service request." : "A request ID is not present in the loaded result." },
    { name: "Source checks", status: checked.length ? (unavailable.length ? "Partial" : "Checks recorded") : "Not recorded", detail: checked.length ? `${checked.length} source check(s) recorded; ${unavailable.length} unavailable or incomplete.` : "Cyclothone has no completed source check recorded in this result." },
    { name: "Evidence", status: findingCount ? "Review signals" : isPartial ? "Incomplete" : "No match recorded", detail: findingCount ? `${findingCount} finding(s) recorded; validate each against its original evidence.` : "Absence of a finding is not proof that the asset is safe." },
    { name: "Case tracking", status: caseId ? "Linked" : "Not linked", detail: caseId ? `Tracked case: ${caseId}` : findingCount ? "A case has not been linked to this result yet." : "No case link is recorded for this result." },
    { name: "Fix verification", status: remediationVerified ? "Verified" : "Not recorded", detail: remediationVerified ? "The result explicitly records remediation verification." : "Cyclothone does not have a verified fix recorded here; do not assume the exposure is resolved." },
  ];

  return <section className="mt-3 space-y-3 rounded-2xl border border-[#91aaab]/20 bg-[#061018]/80 p-4 text-[10px] leading-5">
    <div className="flex flex-wrap items-start justify-between gap-2">
      <div>
        <div className="text-[9px] uppercase tracking-[.16em] text-[#82aab1]">Cyclothone customer guide · {LABELS[service] ?? titleCase(service)}</div>
        <div className="mt-1 text-sm font-semibold text-[#e8f1f3]">{resultTitle}</div>
      </div>
      <span className={"rounded-full border px-2 py-1 " + (findingCount ? "border-[#ffb36b]/30 text-[#ffca91]" : isPartial ? "border-[#ffd27a]/30 text-[#ffd27a]" : "border-[#9ff5c0]/25 text-[#9ff5c0]")}>{findingCount ? `Highest severity: ${titleCase(severity.label)}` : isPartial ? "Coverage incomplete" : "No finding recorded"}</span>
    </div>
    <p className="text-[#b7c9cd]">{explanation}</p>

    <div className="grid gap-3 sm:grid-cols-2">
      <div className="rounded-xl border border-white/[0.07] p-3">
        <div className="text-[9px] uppercase tracking-wider text-[#82aab1]">What this means</div>
        <p className="mt-1 text-[#d9e5e7]">{findingCount ? `The lead signal is “${primaryKind}”. Review the original evidence, confirm that it relates to your organization, and decide whether it is confirmed, benign, or still uncertain.` : isPartial ? "The workflow cannot make a complete statement about exposure while required checks remain unavailable." : "This run did not return a matching signal from the checks that completed. Keep monitoring enabled and consider expanding the approved scope if the asset is high value."}</p>
      </div>
      <div className="rounded-xl border border-white/[0.07] p-3">
        <div className="text-[9px] uppercase tracking-wider text-[#82aab1]">What Cyclothone actually checked</div>
        <p className="mt-1 text-[#d9e5e7]">{checked.length ? `${checked.length} source provider(s) returned a completed check` : "No live source check is listed in the persisted result"}{unavailable.length ? `; ${unavailable.length} provider(s) were unavailable or not completed.` : ". No unavailable provider is listed in this result."}</p>
        {isDarkWeb && sourceCoverage && <p className="mt-1 text-[#d9e5e7]">Actual source coverage: {safeCount(sourceCoverage.providers_checked)} of {safeCount(sourceCoverage.provider_count)} provider calls completed. Telegram public channels: {safeCount(sourceCoverage.telegram_channels_checked)} of {safeCount(sourceCoverage.telegram_channels_total)} checked successfully; {safeCount(sourceCoverage.telegram_channels_failed)} failed.</p>}
        {isDarkWeb && <p className="mt-1 text-[#9fb5bb]">Historical corpus: {corpus ? `${safeCount(scanned)} records scanned · ${safeCount(exactMatches)} exact matches.` : "scan count not recorded for this request."} A corpus record count is not the same as the number of global websites, forums, channels, or people checked.</p>}
      </div>
    </div>

    <div className="rounded-xl border border-[#c2f35a]/15 bg-[#c2f35a]/[0.035] p-3">
      <div className="text-[10px] uppercase tracking-wider text-[#c2f35a]">Recommended next steps</div>
      <ol className="mt-2 list-decimal space-y-1 pl-4 text-[#d9e5e7]">{steps.map((step, i) => <li key={i}>{step}</li>)}</ol>
    </div>

    <div className="rounded-xl border border-[#8ddcff]/20 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="text-[10px] uppercase tracking-wider text-[#8ddcff]">Cyclothone control tower</div>
          <p className="mt-1 text-[#b7c9cd]">A simple, auditable view of what happened and what is still missing. No step is marked complete unless the result records it.</p>
        </div>
        <span className="rounded-full border border-white/10 px-2 py-1 text-[10px]">{stages.filter((stage) => ["Recorded", "Checks recorded", "Linked", "Verified"].includes(stage.status)).length}/5 evidenced</span>
      </div>
      <ol className="mt-3 space-y-2">
        {stages.map((stage, i) => {
          const complete = ["Recorded", "Checks recorded", "Linked", "Verified"].includes(stage.status);
          return <li key={stage.name} className="flex gap-3 rounded-lg border border-white/[0.06] p-3">
            <span className={"flex h-6 w-6 shrink-0 items-center justify-center rounded-full border text-[10px] " + (complete ? "border-[#9ff5c0]/40 text-[#9ff5c0]" : "border-[#ffd27a]/40 text-[#ffd27a]")}>{i + 1}</span>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-medium text-[#e8f1f3]">{stage.name}</span>
                <span className={"text-[10px] " + (complete ? "text-[#9ff5c0]" : "text-[#ffd27a]")}>{stage.status}</span>
              </div>
              <p className="mt-1 text-[#9fb5bb]">{stage.detail}</p>
            </div>
          </li>;
        })}
      </ol>
    </div>

    {findingCount > 0 && !caseId && <div className="rounded-xl border border-[#8ddcff]/20 bg-[#8ddcff]/[0.035] p-3">
      <div className="text-[9px] uppercase tracking-wider text-[#8ddcff]">Continue with a case</div>
      <p className="mt-1 text-[#b7c9cd]">Create a tracked case so your team can assign an owner, record investigation notes, and follow the issue through resolution. Creating a case does not itself remediate the exposure.</p>
      <button type="button" disabled={openingCase || !request.id} onClick={async()=>{setOpeningCase(true);setCaseMessage("");try{const response=await openCustomerCase(String(request.id),service, severity.rank>=3?"high":severity.rank===2?"medium":"low");const id=text(response.case_id);if(id)setCreatedCaseId(id);setCaseMessage(id?`Case created: ${id}`:"Case request accepted; refresh to confirm the case link.");window.dispatchEvent(new Event("cyclothone-refresh-customer-service"));}catch(error){setCaseMessage(error instanceof Error?error.message:"Unable to open a case. Your result remains unchanged.");}finally{setOpeningCase(false)}}} className="mt-2 rounded-full border border-[#8ddcff]/30 px-4 py-2 text-[10px] text-[#8ddcff] disabled:opacity-50">{openingCase?"Opening case…":"Open a tracked case →"}</button>
      {caseMessage && <p role="status" className="mt-2 text-[#b7c9cd]">{caseMessage}</p>}
    </div>}
    {findings.length > 0 && <div className="rounded-xl border border-white/[0.07] p-3">
      <div className="text-[9px] uppercase tracking-wider text-[#82aab1]">Signals to review</div>
      <div className="mt-2 space-y-2">{findings.slice(0, 5).map((finding, i) => <div key={String(finding.id ?? finding.fingerprint ?? i)} className="border-l-2 border-[#ffb36b]/50 pl-3">
        <div className="text-[#e8f1f3]">{text(finding.title, finding.summary, finding.description, "Exposure signal")}</div>
        <div className="text-[#9fb5bb]">{titleCase(exposureKind(finding))} · {titleCase(severityOf(finding))} · {titleCase(text(finding.status, "needs review"))}</div>
      </div>)}</div>
      {evidenceLinks.length > 0 && <div className="mt-2 flex flex-wrap gap-3">{evidenceLinks.map((url) => <a key={url} href={url} target="_blank" rel="noreferrer" className="break-all text-[#8ddcff] underline">Open source evidence ↗</a>)}</div>}
    </div>}

    <div className="flex flex-wrap gap-x-4 gap-y-1 border-t border-white/[0.07] pt-3 text-[#9fb5bb]">
      <span>Workflow state: <strong className="font-medium text-[#e8f1f3]">{state}</strong></span>
      <span>Alerts: <strong className="font-medium text-[#e8f1f3]">{alertCount.toLocaleString()}</strong></span>
      <span>Case: <strong className="font-medium text-[#e8f1f3]">{caseId || "not linked"}</strong></span>
      {request.created_at && <span>Requested: {new Date(request.created_at).toLocaleString()}</span>}
    </div>
    <p className="text-[9px] text-[#718d95]">Customer guidance is generated from this persisted result and available evidence. It does not execute remediation, confirm a breach by itself, or replace your incident-response and legal obligations. A result can only update when the underlying workflow result or source status is refreshed.</p>
  </section>;
}
