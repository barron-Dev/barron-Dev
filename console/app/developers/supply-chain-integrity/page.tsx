"use client";

import Link from "next/link";

const endpoints = [
  ["POST", "/api/v1/global-integrity/challenges", "Issue a three-minute, single-use challenge bound to the tenant, principal, enrolled device, purpose and canonical context."],
  ["POST", "/api/v1/global-integrity/devices/attest", "Register a public key after proof-of-possession. Registration remains UNVERIFIED; this endpoint cannot self-promote hardware assurance."],
  ["POST", "/api/v1/global-integrity/authorize", "Request atomic authorization for a sensitive action. The database rechecks device state, attestation freshness, challenge use and receipt persistence."],
  ["POST", "/api/v1/global-integrity/sbom/scan", "Submit a signed CycloneDX SBOM. Requires a fresh VERIFIED device attestation and source-backed package intelligence."],
  ["POST", "/api/v1/global-integrity/supply-chain/blast-radius", "Read tenant-scoped package impact with a signed, one-time challenge and persisted authorization receipt."],
];

export default function SupplyChainIntegrityDeveloperPage() {
  return (
    <main className="cyclo-water min-h-screen text-[#e8eef6]">
      <header className="border-b border-white/10 bg-[#02090e]/70 px-6 py-4">
        <div className="mx-auto flex max-w-5xl items-center justify-between">
          <Link href="/developers" className="font-semibold tracking-tight">◌ CYCLOTHONE · Developer</Link>
          <Link href="/developers" className="text-xs text-[#9ab0b6]">Developer access</Link>
        </div>
      </header>
      <div className="mx-auto max-w-5xl px-5 py-10 md:px-8">
        <div className="text-[9px] uppercase tracking-[.22em] text-[#4f8494]">Cybersecurity Assessment · API integration</div>
        <h1 className="mt-3 text-3xl font-semibold md:text-5xl">Supply-chain & execution integrity</h1>
        <p className="mt-4 max-w-3xl text-sm leading-7 text-[#91aaab]">Tenant-scoped device trust, signed authorization receipts and software supply-chain evidence. This page documents the API contract and current release gates; it does not imply that hardware verifiers or production database migrations are active.</p>

        <section className="cyclo-stage mt-8 p-6">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h2 className="text-lg font-medium">API surface</h2>
            <span className="rounded-full border border-[#ffd27a]/30 px-3 py-2 text-[9px] uppercase tracking-wider text-[#ffd27a]">Release gated</span>
          </div>
          <div className="mt-5 space-y-3">
            {endpoints.map(([method, path, description]) => (
              <div key={path} className="rounded-2xl border border-white/10 bg-black/20 p-4">
                <div className="flex flex-wrap items-center gap-3"><span className="font-mono text-[9px] text-[#c2f35a]">{method}</span><code className="break-all text-xs text-[#e8eef6]">{path}</code></div>
                <p className="mt-2 text-xs leading-6 text-[#91aaab]">{description}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="mt-5 grid gap-4 md:grid-cols-2">
          <div className="cyclo-stage p-5"><div className="text-[9px] uppercase tracking-wider text-[#688487]">Identity boundary</div><h2 className="mt-2 text-base">Active enrolled device required</h2><p className="mt-2 text-xs leading-6 text-[#91aaab]">The API binds every operation to the authenticated tenant and principal and to an active UUID in the existing platform device registry.</p></div>
          <div className="cyclo-stage p-5"><div className="text-[9px] uppercase tracking-wider text-[#688487]">Cryptographic boundary</div><h2 className="mt-2 text-base">Proof of possession ≠ hardware trust</h2><p className="mt-2 text-xs leading-6 text-[#91aaab]">Ed25519 signatures verify possession of a private key. Only a separately operated, trusted platform verifier can establish hardware or workload assurance.</p></div>
          <div className="cyclo-stage p-5"><div className="text-[9px] uppercase tracking-wider text-[#688487]">Package intelligence</div><h2 className="mt-2 text-base">Unknown is not clean</h2><p className="mt-2 text-xs leading-6 text-[#91aaab]">Malicious or compromised packages block. Suspicious and unknown packages require review. No seeded threat intelligence or synthetic scan results are used.</p></div>
          <div className="cyclo-stage p-5"><div className="text-[9px] uppercase tracking-wider text-[#688487]">Production gate</div><h2 className="mt-2 text-base text-[#ffd27a]">Migrations and verifiers pending</h2><p className="mt-2 text-xs leading-6 text-[#91aaab]">Atomic authorization, revocation lifecycle and verifier-authority migrations are not yet applied to production. No trusted verifier keys or platform verifier agents are provisioned.</p></div>
        </section>

        <section className="cyclo-stage mt-5 p-6">
          <h2 className="text-lg font-medium">Integration rules</h2>
          <ul className="mt-3 list-disc space-y-2 pl-5 text-xs leading-6 text-[#91aaab]">
            <li>Never send a device private key to Cyclothone; signatures are produced by the enrolled endpoint.</li>
            <li>Bind each signature to the exact challenge, purpose, tenant, principal, device and canonical request context.</li>
            <li>Do not retry a consumed challenge; obtain a fresh challenge for each operation.</li>
            <li>Treat blocked, unavailable, stale, unknown and partial outcomes distinctly.</li>
            <li>Do not treat an API response as proof that a downstream action executed; verify the corresponding service evidence and receipt.</li>
          </ul>
        </section>
        <div className="mt-6"><Link href="/developers" className="text-xs text-[#c2f35a]">← Back to developer access</Link></div>
      </div>
    </main>
  );
}
