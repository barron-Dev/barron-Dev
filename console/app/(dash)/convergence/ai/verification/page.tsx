"use client";

import { useState } from "react";

type DemoReport = {
  signatureValid: boolean;
  tamperRejected: boolean;
  payloadHash: string;
  eventHash: string;
  publicKey: string;
  signature: string;
  payload: string;
};

const encoder = new TextEncoder();
const GENESIS = "0".repeat(64);
const DOMAIN = "cyclothone.ai-action.event.v1:";

function canonical(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Non-finite numbers are not valid canonical JSON.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (typeof value === "object") {
    const object = value as Record<string, unknown>;
    return "{" + Object.keys(object).sort().map(key => JSON.stringify(key) + ":" + canonical(object[key])).join(",") + "}";
  }
  throw new Error("Unsupported canonical JSON value.");
}

function hex(bytes: ArrayBuffer | Uint8Array): string {
  return Array.from(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes))
    .map(value => value.toString(16).padStart(2, "0")).join("");
}

async function sha256(text: string): Promise<string> {
  return hex(await crypto.subtle.digest("SHA-256", encoder.encode(text)));
}

function frame(value: string): string {
  return String(encoder.encode(value).length) + ":" + value;
}

function canonicalTimestamp(): string {
  return new Date().toISOString().replace(/\.(\d{3})Z$/, (_match, ms: string) => "." + ms + "000Z");
}

async function computeEventHash(fields: string[]): Promise<string> {
  return sha256(DOMAIN + fields.map(frame).join(""));
}

function signedFields(input: {
  sequence: number; eventId: string; tenantId: string; runId: string; actorId: string;
  agentId: string; actionType: string; payloadHash: string; previousHash: string;
  signerKeyId: string; occurredAt: string;
}): string[] {
  return [
    String(input.sequence), input.eventId, input.tenantId, input.runId,
    input.actorId, input.agentId, input.actionType, input.payloadHash,
    input.previousHash, input.signerKeyId, input.occurredAt,
  ];
}

export default function AIActionVerificationDemo() {
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState<DemoReport | null>(null);
  const [error, setError] = useState("");

  async function runSelfTest() {
    setBusy(true);
    setReport(null);
    setError("");
    try {
      if (!crypto?.subtle || typeof crypto.randomUUID !== "function") {
        throw new Error("This browser does not provide the required Web Crypto APIs.");
      }
      const pair = await crypto.subtle.generateKey(
        { name: "Ed25519" } as AlgorithmIdentifier, true, ["sign", "verify"],
      ) as CryptoKeyPair;
      const payloadObject = {
        action: "tool.execute",
        args: { target: "demo-resource" },
        policy: "demo-only",
        request_id: crypto.randomUUID(),
      };
      const payload = canonical(payloadObject);
      const payloadHash = await sha256(payload);
      const fields = {
        sequence: 1,
        eventId: crypto.randomUUID(),
        tenantId: crypto.randomUUID(),
        runId: crypto.randomUUID(),
        actorId: "browser-local-demo",
        agentId: crypto.randomUUID(),
        actionType: "tool.execute",
        payloadHash,
        previousHash: GENESIS,
        signerKeyId: "ephemeral-browser-demo-key",
        occurredAt: canonicalTimestamp(),
      };
      const eventHash = await computeEventHash(signedFields(fields));
      const algorithm = { name: "Ed25519" } as AlgorithmIdentifier;
      const signature = await crypto.subtle.sign(algorithm, pair.privateKey, encoder.encode(eventHash));
      const signatureValid = await crypto.subtle.verify(algorithm, pair.publicKey, signature, encoder.encode(eventHash));

      // Alter one signed field, recompute the event digest, and try the original
      // signature. Web Crypto must reject the modified receipt.
      const changedPayload = canonical({ ...payloadObject, args: { target: "tampered-resource" } });
      const changedPayloadHash = await sha256(changedPayload);
      const changedEventHash = await computeEventHash(signedFields({ ...fields, payloadHash: changedPayloadHash }));
      const tamperedSignatureAccepted = await crypto.subtle.verify(
        algorithm, pair.publicKey, signature, encoder.encode(changedEventHash),
      );
      const publicKey = hex(await crypto.subtle.exportKey("raw", pair.publicKey));
      setReport({
        signatureValid,
        tamperRejected: !tamperedSignatureAccepted,
        payloadHash,
        eventHash,
        publicKey,
        signature: hex(signature),
        payload,
      });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Cryptographic self-test failed.");
    } finally {
      setBusy(false);
    }
  }

  const success = Boolean(report?.signatureValid && report?.tamperRejected);
  return (
    <main className="min-h-screen bg-[#05070a] p-6 text-[#e8eef6]">
      <div className="mx-auto max-w-4xl space-y-5">
        <header>
          <div className="text-[10px] uppercase tracking-[.16em] text-[#5a6675]">AI Trust / Verification</div>
          <h1 className="mt-1 text-2xl font-semibold">Cryptographic AI Action Verifier</h1>
          <p className="mt-2 max-w-3xl text-sm text-[#8a97a8]">
            A real local Web Crypto self-test: generate an ephemeral Ed25519 key, sign a canonical action receipt,
            verify it, then alter a signed payload field and prove the original signature no longer verifies.
          </p>
        </header>

        <section className="border border-amber-400/40 bg-amber-400/5 p-4 text-xs text-amber-200">
          <strong>LOCAL DEMONSTRATION ONLY.</strong> This generates an ephemeral key and synthetic test payload inside this browser.
          It does not call the production API, use a registered Cyclothone key, or establish the authenticity of a real action.
          No result is shown as verified until the cryptographic checks actually run.
        </section>

        <section className="space-y-4 border border-[#1a2330] bg-[#0a0e14] p-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="text-xs uppercase tracking-[.12em] text-[#5a6675]">Proof gates</div>
              <p className="mt-1 text-sm text-[#8a97a8]">SHA-256 payload commitment · domain-separated event hash · Ed25519 verification · tamper rejection</p>
            </div>
            <button disabled={busy} onClick={() => void runSelfTest()}
              className="h-10 border border-[#00d9ff] px-4 text-xs text-[#00d9ff] disabled:opacity-50">
              {busy ? "Running cryptographic checks…" : "Run real cryptographic self-test"}
            </button>
          </div>
          {error && <div role="alert" className="border border-[#ff2d55]/40 bg-[#ff2d55]/5 p-3 text-xs text-[#ff6b83]">{error}</div>}
          {report && <>
            <div className={"border p-4 " + (success ? "border-emerald-400/40 bg-emerald-400/5" : "border-[#ff2d55]/40 bg-[#ff2d55]/5")}>
              <div className={"text-sm font-semibold " + (success ? "text-emerald-300" : "text-[#ff6b83]")}>
                {success ? "Self-test passed — original valid, tampered receipt rejected" : "Self-test failed — do not treat this result as verified"}
              </div>
              <div className="mt-3 grid gap-3 md:grid-cols-2">
                <div><div className="text-[10px] uppercase text-[#5a6675]">Original signature</div><div className="mt-1 font-mono text-xs">{report.signatureValid ? "PASS — verified" : "FAIL — not verified"}</div></div>
                <div><div className="text-[10px] uppercase text-[#5a6675]">Modified payload</div><div className="mt-1 font-mono text-xs">{report.tamperRejected ? "PASS — rejected" : "FAIL — signature accepted"}</div></div>
              </div>
            </div>
            <dl className="grid gap-3 border border-[#1a2330] bg-[#030508] p-4">
              <div><dt className="text-[10px] uppercase text-[#5a6675]">Canonical payload (local fixture)</dt><dd className="mt-1 break-all font-mono text-xs">{report.payload}</dd></div>
              <div><dt className="text-[10px] uppercase text-[#5a6675]">Payload SHA-256</dt><dd className="mt-1 break-all font-mono text-xs">{report.payloadHash}</dd></div>
              <div><dt className="text-[10px] uppercase text-[#5a6675]">Event SHA-256</dt><dd className="mt-1 break-all font-mono text-xs">{report.eventHash}</dd></div>
              <div><dt className="text-[10px] uppercase text-[#5a6675]">Ephemeral public key (raw hex)</dt><dd className="mt-1 break-all font-mono text-xs">{report.publicKey}</dd></div>
              <div><dt className="text-[10px] uppercase text-[#5a6675]">Ed25519 signature (hex)</dt><dd className="mt-1 break-all font-mono text-xs">{report.signature}</dd></div>
            </dl>
          </>}
        </section>
        <p className="text-[11px] leading-5 text-[#5a6675]">
          Security boundary: a valid signature proves only that the corresponding key signed these bytes. Production acceptance still requires
          server-side identity and policy checks, a registered non-revoked key, database-side hash/signature recomputation, replay protection,
          and durable evidence read-back. This page does not claim those production gates are connected yet.
        </p>
      </div>
    </main>
  );
}
