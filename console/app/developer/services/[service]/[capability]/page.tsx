"use client";

import Link from "next/link";
import { useParams } from "next/navigation";

const CAPABILITIES = {
  "action-verification": {
    title: "AI Action Verification",
    summary: "Verify signed AI action receipts and preserve a tamper-evident evidence chain.",
    boundary: "The cryptographic envelope, hash-chain and Ed25519 verifier foundations exist in a separate draft workstream. No customer-facing verification is activated from this page.",
    gates: [
      "Reconcile the production migration ledger with authoritative source files and live schema before any DDL.",
      "Provision a tenant-scoped signing key through approved backend key custody and register only its public key through the trusted service path.",
      "Prove authenticated API-to-database E2E for valid receipts, forged signatures, cross-tenant/run replay, concurrent replay claims and durable read-back.",
      "Verify key revocation/rotation, authorization scopes, append-only grants and failure behavior."
    ],
    pr: "https://github.com/barron-Dev/barron-Dev/pull/94"
  },
  "omni-vision": {
    title: "Omni-Vision",
    summary: "Preserve original media provenance and produce verifiable evidence across CAM, FILE, AUDIO, DOC and ENV modalities.",
    boundary: "The current separate workstream provides local evidence primitives only. This page does not claim real media ingestion, detector inference, production storage or source authenticity.",
    gates: [
      "Bind tenant authorization and key IDs to the existing trusted public-key directory.",
      "Implement authenticated ingestion that hashes exact original bytes before decoding and records derived artifacts with provenance.",
      "Use actual version-pinned modality runtime/model artifacts; absent sources or models must produce unavailable/partial coverage, never fabricated detections.",
      "Persist evidence atomically through an authenticated backend/RPC and test tamper, replay, revocation, cross-tenant access and interrupted sync."
    ],
    pr: "https://github.com/barron-Dev/barron-Dev/pull/95"
  }
} as const;

export default function DeveloperAICapabilityGatePage() {
  const params = useParams<{ service: string; capability: string }>();
  const capability = params?.capability as keyof typeof CAPABILITIES;
  const item = CAPABILITIES[capability];
  if (params?.service !== "ai_security" || !item) {
    return <main className="min-h-screen bg-[#050b16] p-6 text-slate-100"><p>AI Security capability workspace not found.</p><Link href="/developer/services/ai_security" className="underline">Back to AI Security</Link></main>;
  }
  return <main className="min-h-screen bg-[#050b16] p-6 text-slate-100">
    <div className="mx-auto max-w-4xl space-y-6">
      <nav className="text-sm text-slate-400"><Link href="/developer/services/ai_security" className="underline">AI Security</Link> / {item.title}</nav>
      <header><p className="text-xs uppercase tracking-[.2em] text-amber-300">Release gates open · not production-ready</p><h1 className="mt-2 text-3xl font-semibold">{item.title}</h1><p className="mt-3 text-sm leading-6 text-slate-300">{item.summary}</p></header>
      <section className="rounded-xl border border-amber-300/20 bg-slate-900/60 p-5"><h2 className="font-semibold">Current implementation boundary</h2><p className="mt-3 text-sm leading-6 text-slate-300">{item.boundary}</p><p className="mt-3 text-xs text-slate-500">This is a build/release status, not a live runtime health result.</p></section>
      <section className="rounded-xl border border-slate-700 p-5"><h2 className="font-semibold">Remaining release gates</h2><ol className="mt-4 list-decimal space-y-3 pl-5 text-sm leading-6 text-slate-300">{item.gates.map(gate => <li key={gate}>{gate}</li>)}</ol></section>
      <div className="flex flex-wrap gap-3"><a href={item.pr} target="_blank" rel="noreferrer" className="rounded-lg border border-slate-600 px-4 py-2 text-sm text-cyan-300 underline">Open source workstream PR →</a><Link href="/developer/services/ai_security/watchtower" className="rounded-lg border border-slate-600 px-4 py-2 text-sm">Watchtower workflow</Link></div>
    </div>
  </main>;
}
