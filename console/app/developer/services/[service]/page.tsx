"use client";

import { useParams } from "next/navigation";
import Link from "next/link";

export default function DeveloperServiceWorkspace() {
  const params = useParams<{ service: string }>();
  const service = params?.service;
  if (service !== "ai_security") {
    return <main className="min-h-screen bg-[#050b16] p-6 text-slate-100"><p>Developer workspace not found for this service.</p><Link href="/developer/services" className="underline">Back to services</Link></main>;
  }
  return <main className="min-h-screen bg-[#050b16] p-6 text-slate-100">
    <div className="mx-auto max-w-6xl space-y-6">
      <nav className="text-sm text-slate-400"><Link href="/developer/services" className="underline">Services</Link> / AI Security</nav>
      <header><p className="text-xs uppercase tracking-[.2em] text-cyan-300">Service 09 · Engineering workspace</p><h1 className="mt-2 text-3xl font-semibold">AI Security</h1><p className="mt-3 max-w-3xl text-sm leading-6 text-slate-300">Governed AI-assisted security and dedicated AI trust services. These are release gates from the current source workstreams, not live health checks or production-readiness claims.</p></header>
      <section className="grid gap-4 md:grid-cols-3">
        <article className="rounded-xl border border-slate-700 bg-slate-900/60 p-5"><h2 className="font-semibold">Watchtower</h2><p className="mt-2 text-sm leading-6 text-slate-400">Camera registry and authenticated probe/history routes exist in source. Real camera handshake, network egress controls, detector runtime and durable signed evidence remain release gates.</p><Link href="/developer/services/ai_security/watchtower" className="mt-4 inline-block text-sm text-cyan-300 underline">Open Watchtower diagnostics →</Link></article>
        <Link href="/developer/services/ai_security/action-verification" className="rounded-xl border border-amber-300/20 bg-slate-900/60 p-5 hover:border-amber-300/40"><h2 className="font-semibold">AI Action Verification</h2><p className="mt-2 text-sm leading-6 text-slate-400">Ed25519 and hash-chain foundations are in a separate draft PR. Required: approved tenant key custody, reconciled migration history, and authenticated API-to-database E2E for forged, replayed and cross-tenant receipts.</p><span className="mt-4 inline-block text-xs text-amber-300">Review release gates →</span></Link>
        <Link href="/developer/services/ai_security/omni-vision" className="rounded-xl border border-amber-300/20 bg-slate-900/60 p-5 hover:border-amber-300/40"><h2 className="font-semibold">Omni-Vision</h2><p className="mt-2 text-sm leading-6 text-slate-400">Signed evidence primitives are in a separate draft PR. Real media ingestion, tenant-bound public-key lookup, modality runtime adapters and atomic durable evidence persistence remain unverified.</p><span className="mt-4 inline-block text-xs text-amber-300">Review release gates →</span></Link>
      </section>
      <section className="rounded-xl border border-slate-700 p-5"><h2 className="font-semibold">Shared release gates</h2><ul className="mt-3 list-disc space-y-2 pl-5 text-sm leading-6 text-slate-300"><li>Reconcile all production migration history and current schema before any DDL.</li><li>Configure real AI provider/model routes and verify execution bindings; empty configuration is not healthy.</li><li>Prove tenant, role, key lifecycle, replay, tamper and failure-path behavior through authenticated end-to-end tests.</li><li>Complete privacy/retention, network-egress, alerting and evidence-custody review.</li></ul><p className="mt-4 text-xs text-slate-500">No secret provisioning, production migration, merge or deployment is performed by this workspace.</p></section>
    </div>
  </main>;
}
