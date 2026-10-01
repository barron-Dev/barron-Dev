"use client";

import { useState } from "react";
import { apiFetch } from "../../../../lib/api";

type Result = {
  score: number;
  verdict: string;
  category: string | null;
  signals: Array<{ name: string; weight: number }>;
  urls: string[];
  wallets: string[];
  input_sha256: string;
  raw_text_persisted: boolean;
};

export default function ScamPage() {
  const [text, setText] = useState("");
  const [sender, setSender] = useState("");
  const [result, setResult] = useState<Result | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function analyze() {
    setBusy(true);
    setError("");
    setResult(null);
    try {
      if (!text.trim()) throw new Error("Message text is required.");
      const data = await apiFetch<Result>("/api/v1/intelligence/scam/message", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text, sender: sender || null }),
      });
      setResult(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Scam analysis failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="min-h-screen bg-[#05070a] p-6 text-[#e8eef6]">
      <div className="mx-auto max-w-5xl space-y-5">
        <header>
          <div className="text-[10px] uppercase tracking-[.16em] text-[#5a6675]">Intelligence</div>
          <h1 className="mt-1 text-2xl font-semibold">Scam Intelligence</h1>
          <p className="mt-1 text-xs text-[#8a97a8]">Analyze message signals through the authenticated Cyclothone API. Raw message content is not persisted by this detector.</p>
        </header>

        <section className="border border-[#1a2330] bg-[#0a0e14] p-5 space-y-4">
          <label className="block text-xs text-[#8a97a8]">Sender ID
            <input value={sender} onChange={e => setSender(e.target.value)} maxLength={64} className="mt-1 h-9 w-full border border-[#2a3646] bg-[#030508] px-2 text-sm" placeholder="Optional sender" />
          </label>
          <label className="block text-xs text-[#8a97a8]">Message
            <textarea value={text} onChange={e => setText(e.target.value)} maxLength={10000} rows={8} className="mt-1 w-full border border-[#2a3646] bg-[#030508] p-2 text-sm" placeholder="Paste a suspicious message for analysis." />
          </label>
          <button disabled={busy} onClick={() => void analyze()} className="h-9 rounded border border-[#00d9ff] px-4 text-xs text-[#00d9ff] disabled:opacity-50">
            {busy ? "Analyzing…" : "Analyze message"}
          </button>
          {error && <div role="alert" className="border border-[#ff2d55]/40 bg-[#ff2d55]/5 p-3 text-xs text-[#ff6b83]">{error}</div>}
        </section>

        {result && (
          <section className="border border-[#1a2330] bg-[#0a0e14] p-5">
            <div className="grid gap-4 md:grid-cols-3">
              <div><div className="text-[10px] uppercase text-[#5a6675]">Verdict</div><div className="mt-1 text-lg font-semibold">{result.verdict}</div></div>
              <div><div className="text-[10px] uppercase text-[#5a6675]">Score</div><div className="mt-1 font-mono text-lg">{result.score.toFixed(3)}</div></div>
              <div><div className="text-[10px] uppercase text-[#5a6675]">Category</div><div className="mt-1 text-lg">{result.category ?? "none"}</div></div>
            </div>
            <div className="mt-5 grid gap-4 md:grid-cols-2">
              <div><div className="text-[10px] uppercase text-[#5a6675]">Signals</div><pre className="mt-2 whitespace-pre-wrap text-xs">{JSON.stringify(result.signals, null, 2)}</pre></div>
              <div><div className="text-[10px] uppercase text-[#5a6675]">Extracted indicators</div><pre className="mt-2 whitespace-pre-wrap text-xs">{JSON.stringify({ urls: result.urls, wallets: result.wallets }, null, 2)}</pre></div>
            </div>
            <div className="mt-5 text-[10px] text-[#5a6675]">Input SHA-256: <span className="font-mono">{result.input_sha256}</span> · raw persistence: {String(result.raw_text_persisted)}</div>
          </section>
        )}
      </div>
    </main>
  );
}
