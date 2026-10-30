"use client";

import { useState } from "react";
import { apiDownload, apiFetch } from "../../../lib/api";

type Verification = {
  receipt_id: string;
  validation_state: "VALID" | "INVALID" | "UNTRUSTED" | "MISSING_PROVENANCE" | "INDETERMINATE";
  media_sha256: string;
  manifest_store_sha256: string | null;
  signer: string | null;
  trust_policy: string;
  trust_policy_version: string;
  sdk_version: string;
  receipt_hash: string;
  cryptographic_proof: { algorithm: string; signature: string; key_id: string; public_key: string };
  interpretation_limit: string;
};

const labels: Record<Verification["validation_state"], string> = {
  VALID: "C2PA verified against configured trust policy",
  INVALID: "Integrity or signature verification failed",
  UNTRUSTED: "Signature present, certificate not trusted",
  MISSING_PROVENANCE: "No C2PA provenance found",
  INDETERMINATE: "Unable to determine provenance",
};

const stateClass: Record<Verification["validation_state"], string> = {
  VALID: "border-emerald-500/40 text-emerald-300",
  INVALID: "border-red-500/40 text-red-300",
  UNTRUSTED: "border-amber-500/40 text-amber-300",
  MISSING_PROVENANCE: "border-slate-500/40 text-slate-300",
  INDETERMINATE: "border-slate-500/40 text-slate-300",
};

export default function ProvenancePage() {
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<Verification | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function verify() {
    if (!file) return;
    setBusy(true); setError(""); setResult(null);
    try {
      const body = new FormData();
      body.append("file", file);
      const response = await apiFetch<Verification>("/api/v1/media/verify-provenance", { method: "POST", body });
      setResult(response);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Verification could not be completed.");
    } finally {
      setBusy(false);
    }
  }

  async function downloadBundle() {
    if (!result) return;
    try {
      await apiDownload(`/api/v1/media/receipts/${encodeURIComponent(result.receipt_id)}/bundle`, `cyclothone-${result.receipt_id}.ctprove`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Evidence bundle download failed.");
    }
  }

  return (
    <main className="min-h-screen bg-[#05070a] p-6 text-[#e8eef6]">
      <div className="mx-auto max-w-5xl space-y-6">
        <header>
          <div className="text-[10px] uppercase tracking-[.16em] text-[#5a6675]">Developer API · Synthetic-Media Provenance</div>
          <h1 className="mt-1 text-2xl font-semibold">Synthetic-Media Provenance</h1>
          <p className="mt-2 max-w-3xl text-sm text-[#8a97a8]">Verify C2PA manifests, hard bindings, signatures and configured certificate trust. Cryptographic provenance is separate from any probabilistic AI assessment.</p>
        </header>

        <section className="space-y-4 border border-[#1a2330] bg-[#080b10] p-5">
          <h2 className="text-sm font-semibold">Verify media provenance</h2>
          <input type="file" accept="image/*,video/*,audio/*,application/pdf" onChange={e => { setFile(e.target.files?.[0] ?? null); setResult(null); setError(""); }} className="block w-full text-xs text-[#aebbc9]" />
          <button onClick={() => void verify()} disabled={!file || busy} className="h-10 rounded-md bg-[#2563eb] px-5 text-sm font-medium text-white disabled:opacity-50">{busy ? "Verifying…" : "Verify C2PA provenance"}</button>
          {error && <p role="alert" className="text-sm text-red-300">{error}</p>}
        </section>

        {result && (
          <section className="space-y-4 border border-[#1a2330] bg-[#080b10] p-5">
            <div className={`inline-flex border px-3 py-2 text-sm font-semibold ${stateClass[result.validation_state]}`}>{result.validation_state} · {labels[result.validation_state]}</div>
            <p className="text-xs text-[#8a97a8]">{result.interpretation_limit}</p>
            <dl className="grid gap-3 text-xs md:grid-cols-2">
              <div><dt className="text-[#5a6675]">Media SHA-256</dt><dd className="mt-1 break-all font-mono">{result.media_sha256}</dd></div>
              <div><dt className="text-[#5a6675]">Manifest-store SHA-256</dt><dd className="mt-1 break-all font-mono">{result.manifest_store_sha256 ?? "Not present"}</dd></div>
              <div><dt className="text-[#5a6675]">Signer claim</dt><dd className="mt-1">{result.signer ?? "Not supplied"}</dd></div>
              <div><dt className="text-[#5a6675]">Trust policy</dt><dd className="mt-1">{result.trust_policy} · {result.trust_policy_version}</dd></div>
              <div><dt className="text-[#5a6675]">Receipt hash</dt><dd className="mt-1 break-all font-mono">{result.receipt_hash}</dd></div>
              <div><dt className="text-[#5a6675]">Receipt signature</dt><dd className="mt-1">{result.cryptographic_proof.algorithm} · {result.cryptographic_proof.key_id}</dd></div>
            </dl>
            <button onClick={() => void downloadBundle()} className="h-9 border border-[#344154] px-4 text-xs text-[#dce6f2]">Download .ctprove evidence bundle</button>
          </section>
        )}

        <section className="border border-[#1a2330] p-4 text-xs text-[#8a97a8]">
          <strong className="text-[#cbd5e1]">Interpretation rule:</strong> VALID means the C2PA SDK validated the manifest and signature using the active configured trust anchors. It does not prove who is depicted, that the scene is true, or that the signer’s claims are factually accurate. Missing provenance is not a finding of manipulation.
        </section>
      </div>
    </main>
  );
}
