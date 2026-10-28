"use client";

import Link from "next/link";

export default function AIActionVerificationPage() {
  return (
    <main className="min-h-screen bg-[#05070a] p-6 text-[#e8eef6]">
      <div className="mx-auto max-w-4xl space-y-5">
        <header>
          <div className="text-[10px] uppercase tracking-[.16em] text-[#5a6675]">AI Trust / Verification</div>
          <h1 className="mt-1 text-2xl font-semibold">Cryptographic AI Action Verifier</h1>
          <p className="mt-2 max-w-3xl text-sm text-[#8a97a8]">
            Production verification status. This page does not generate local keys, synthetic actions, or simulated verification receipts.
          </p>
        </header>

        <section className="border border-amber-400/40 bg-amber-400/5 p-4 text-sm text-amber-200" role="status">
          <strong>BLOCKED — production verification is not yet proven.</strong>
          <p className="mt-2">
            The server-side verifier, registered production signing key, database-side Ed25519 verification, and durable receipt read-back
            have not been demonstrated together against the live service. No verification result is available to display.
          </p>
        </section>

        <section className="space-y-3 border border-[#1a2330] bg-[#0a0e14] p-5">
          <h2 className="text-sm font-semibold">Required evidence before this can report a result</h2>
          <ul className="list-disc space-y-2 pl-5 text-sm text-[#aeb8c6]">
            <li>An authenticated, tenant-scoped AI run and action sourced from persisted production records.</li>
            <li>A registered, active signing-key identity with private-key custody outside the database and browser.</li>
            <li>Server-side signature and canonical-payload verification, including tenant, run, agent, policy, and replay bindings.</li>
            <li>A committed append-only receipt read back from the database and verified against the stored event chain.</li>
            <li>An authenticated end-to-end test that exercises the real API and database, not a browser-local fixture or mocked provider.</li>
          </ul>
        </section>

        <section className="border border-[#1a2330] bg-[#0a0e14] p-5">
          <h2 className="text-sm font-semibold">Current limitation</h2>
          <p className="mt-2 text-sm leading-6 text-[#aeb8c6]">
            The implementation branch contains verifier primitives and a database migration candidate, but the live database cryptographic
            function and production key registration are not yet verified. This page therefore exposes no pass/fail badge, generated signature,
            fabricated event, or synthetic result.
          </p>
          <Link href="/convergence/ai" className="mt-4 inline-block border border-[#2a3646] px-4 py-2 text-xs text-[#e8eef6] hover:border-[#00d9ff]">
            Return to AI Security Runtime
          </Link>
        </section>
      </div>
    </main>
  );
}
