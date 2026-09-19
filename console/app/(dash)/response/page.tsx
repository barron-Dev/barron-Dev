"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "../../../../lib/api";

type Row = Record<string, unknown>;

export default function ResponsePage() {
  const [playbooks, setPlaybooks] = useState<Row[]>([]);
  const [runs, setRuns] = useState<Row[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    void (async () => {
      try {
        const [p, r] = await Promise.all([
          apiFetch<unknown>("/api/v1/console/response/playbooks"),
          apiFetch<unknown>("/api/v1/console/response/runs"),
        ]);
        setPlaybooks(Array.isArray(p) ? p as Row[] : [p as Row]);
        setRuns(Array.isArray(r) ? r as Row[] : [r as Row]);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Could not load response data");
      }
    })();
  }, []);

  return (
    <main className="min-h-screen bg-[#05070a] p-6 text-[#e8eef6]">
      <div className="mx-auto max-w-6xl space-y-5">
        <header>
          <div className="text-[10px] uppercase tracking-[.16em] text-[#5a6675]">Operations</div>
          <h1 className="mt-1 text-2xl font-semibold">Response</h1>
          <p className="mt-1 text-xs text-[#8a97a8]">Live response playbooks and execution runs. Approval and rollback remain server-authorized.</p>
        </header>
        {error && <div role="alert" className="border border-[#ff2d55]/40 bg-[#ff2d55]/5 p-3 text-xs text-[#ff6b83]">{error}</div>}
        <section className="border border-[#1a2330] bg-[#0a0e14] p-5">
          <h2 className="text-sm font-semibold">Playbooks</h2>
          <pre className="mt-3 max-h-[28rem] overflow-auto whitespace-pre-wrap break-words text-xs">{JSON.stringify(playbooks, null, 2)}</pre>
        </section>
        <section className="border border-[#1a2330] bg-[#0a0e14] p-5">
          <h2 className="text-sm font-semibold">Runs</h2>
          <pre className="mt-3 max-h-[28rem] overflow-auto whitespace-pre-wrap break-words text-xs">{JSON.stringify(runs, null, 2)}</pre>
        </section>
      </div>
    </main>
  );
}
