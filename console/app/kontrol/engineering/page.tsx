"use client";

import Link from "next/link";
import { FormEvent, useState } from "react";
import { apiFetch } from "@/lib/api";

type Message = { role: "user" | "assistant"; content: string; createdAt: string };
type ChatResponse = { answer: string; thread_id?: string; mode?: string; infrastructure_tools_connected?: boolean; note?: string };

const workspaces = [
  { title: "GitHub", detail: "Repository, branches, PRs, checks and code changes", mark: "GH" },
  { title: "Vercel", detail: "Deployments, build outcomes, aliases and production routes", mark: "VC" },
  { title: "Supabase", detail: "Schema, migrations, RPCs, RLS and production readback", mark: "SB" },
  { title: "Railway", detail: "Service state, deployments, logs and runtime health", mark: "RW" },
];

const guardrails = [
  "Evidence before claims: link findings to actual source responses.",
  "Read-first workflow: inspect current state before proposing changes.",
  "Approval gates: no sensitive writes, production deploys, restarts or secret changes without authorization.",
  "Verify after action: report changed, blocked and unverified separately.",
];

export default function EngineeringAIPage() {
  const [input, setInput] = useState("");
  const [messages, setMessages] = useState<Message[]>([]);
  const [threadId] = useState(() => crypto.randomUUID());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [connection, setConnection] = useState<"unknown" | "connected" | "unavailable">("unknown");

  async function send(event?: FormEvent) {
    event?.preventDefault();
    const prompt = input.trim();
    if (!prompt || busy) return;
    setInput("");
    setError("");
    setMessages((items) => [...items, { role: "user", content: prompt, createdAt: new Date().toISOString() }]);
    setBusy(true);
    try {
      const result = await apiFetch<ChatResponse>("/api/v1/kontrol/engineering/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ thread_id: threadId, message: prompt, history: [...messages, { role: "user" as const, content: prompt, createdAt: new Date().toISOString() }].slice(-20).map(({ role, content }) => ({ role, content })) }),
      });
      if (!result || typeof result.answer !== "string" || !result.answer.trim()) {
        throw new Error("Engineering AI returned no verifiable answer.");
      }
      setConnection("connected");
      const answer = result.infrastructure_tools_connected === false ? `${result.answer}\n\n— Integration status: no infrastructure connector returned a successful result for this response. Check the reported tool outcomes before treating live state as verified.` : result.answer;
      setMessages((items) => [...items, { role: "assistant", content: answer, createdAt: new Date().toISOString() }]);
    } catch (cause) {
      setConnection("unavailable");
      setError(cause instanceof Error ? cause.message : "Engineering AI service unavailable.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="min-h-screen bg-[#05070a] text-[#e8eef6]">
      <header className="sticky top-0 z-20 flex min-h-16 flex-wrap items-center justify-between gap-3 border-b border-[#1a2937] bg-[#080d13]/95 px-5 backdrop-blur">
        <div><Link href="/kontrol" className="font-semibold tracking-wide hover:text-[#00d9ff]">CYCLOTHONE <span className="ml-2 font-mono text-[10px] text-[#00d9ff]">KONTROL</span></Link><div className="mt-1 text-[10px] uppercase tracking-[.18em] text-[#b8f37d]">Layer 2 · Engineering AI</div></div>
        <div className="flex items-center gap-3 text-xs"><span className={connection === "connected" ? "text-[#b8f37d]" : connection === "unavailable" ? "text-[#ff8ca0]" : "text-[#8291a3]"}>{connection === "connected" ? "Service responded" : connection === "unavailable" ? "Backend unavailable" : "Connection not yet verified"}</span><Link href="/kontrol" className="border border-[#2a3646] px-3 py-2 hover:border-[#00d9ff]/50">← Command Center</Link></div>
      </header>

      <div className="mx-auto grid max-w-[1600px] gap-5 p-4 md:p-6 xl:grid-cols-[minmax(0,1fr)_330px]">
        <section className="flex min-h-[calc(100vh-120px)] flex-col overflow-hidden border border-[#1a2937] bg-[#080e15]">
          <div className="border-b border-[#1a2937] bg-[#0a131d] p-5 md:p-6">
            <div className="font-mono text-[10px] uppercase tracking-[.2em] text-[#b8f37d]">Engineering workbench</div>
            <h1 className="mt-2 text-2xl font-semibold md:text-3xl">Engineering AI</h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-[#91a1b4]">A dedicated engineering seat for diagnosis, implementation planning, code review, production verification and cross-system coordination. It must ground every operational claim in real tool results.</p>
          </div>

          <div className="flex-1 space-y-4 overflow-y-auto p-4 md:p-6">
            {messages.length === 0 && <div className="mx-auto max-w-3xl py-8">
              <div className="border border-[#243547] bg-[#0b1621] p-5 md:p-6">
                <div className="font-mono text-[10px] uppercase tracking-[.18em] text-[#00d9ff]">Start a task</div>
                <h2 className="mt-2 text-lg font-medium">What should we investigate or build?</h2>
                <p className="mt-2 text-sm leading-6 text-[#91a1b4]">Ask for a code trace, a production-state comparison, a migration review, an implementation plan or a verification report. The assistant must not claim it ran a tool unless the backend confirms it.</p>
                <div className="mt-5 grid gap-2 sm:grid-cols-2">
                  {["Trace the Dark Web request-to-evidence path", "Compare main with the live production deployment", "Find missing API routes and frontend wiring", "Review migration safety and read back production state"].map((suggestion) => <button key={suggestion} type="button" onClick={() => setInput(suggestion)} className="border border-[#1d3041] bg-[#08111a] p-3 text-left text-xs leading-5 text-[#b1c0d0] hover:border-[#00d9ff]/50 hover:text-white">{suggestion} <span className="float-right text-[#00d9ff]">↗</span></button>)}
                </div>
              </div>
            </div>}

            {messages.map((message, index) => <article key={index} className={message.role === "user" ? "ml-auto max-w-3xl border border-[#284455] bg-[#0d1d29] p-4" : "mr-auto max-w-4xl border border-[#26313d] bg-[#0b1118] p-4"}>
              <div className="mb-2 font-mono text-[9px] uppercase tracking-[.16em] text-[#00d9ff]">{message.role === "user" ? "You" : "Engineering AI"}</div>
              <p className="whitespace-pre-wrap break-words text-sm leading-6">{message.content}</p>
            </article>)}
            {busy && <div role="status" className="border border-[#26313d] bg-[#0b1118] p-4 text-sm text-[#91a1b4]"><span className="mr-2 inline-block h-2 w-2 animate-pulse rounded-full bg-[#00d9ff]" />Waiting for authenticated engineering service…</div>}
            {error && <div role="alert" className="border border-[#ff2d55]/40 bg-[#ff2d55]/5 p-4 text-sm leading-6 text-[#ff8ca0]"><strong className="block">No assistant answer was recorded.</strong><span>{error}</span><p className="mt-2 text-xs text-[#d5a1aa]">This is a real service failure, not a simulated response. The interface will not substitute a canned answer.</p></div>}
          </div>

          <form onSubmit={send} className="border-t border-[#1a2937] bg-[#0a1119] p-4 md:p-5">
            <label htmlFor="engineering-prompt" className="mb-2 block text-[10px] uppercase tracking-[.16em] text-[#8291a3]">Engineering request</label>
            <div className="flex items-end gap-2">
              <textarea id="engineering-prompt" value={input} onChange={(event) => setInput(event.target.value)} maxLength={12000} rows={3} placeholder="Describe the engineering task, failure, or implementation you want verified…" className="min-h-14 flex-1 resize-y border border-[#26394a] bg-[#050a10] p-3 text-sm outline-none focus:border-[#00d9ff]/60" />
              <button type="submit" disabled={busy || !input.trim()} className="min-h-12 border border-[#b8f37d]/50 bg-[#b8f37d]/10 px-4 text-sm text-[#c7ff91] hover:bg-[#b8f37d]/15 disabled:cursor-not-allowed disabled:opacity-40">{busy ? "Working…" : "Send ↗"}</button>
            </div>
            <div className="mt-2 flex flex-wrap justify-between gap-2 text-[10px] text-[#647386]"><span>Authenticated backend required · No synthetic answers</span><span>{input.length}/12000</span></div>
          </form>
        </section>

        <aside className="space-y-4">
          <section className="border border-[#1a2937] bg-[#080e15] p-4">
            <div className="font-mono text-[10px] uppercase tracking-[.18em] text-[#00d9ff]">Tool workspace</div>
            <h2 className="mt-2 text-base font-semibold">Engineering systems</h2>
            <p className="mt-2 text-xs leading-5 text-[#8190a3]">These are required integration domains, not a claim that every connector is currently authenticated.</p>
            <div className="mt-4 space-y-2">{workspaces.map((item) => <div key={item.mark} className="border border-[#1c2a37] bg-[#0a121b] p-3"><div className="flex items-center gap-3"><span className="flex h-8 w-8 items-center justify-center border border-[#284052] font-mono text-[10px] text-[#00d9ff]">{item.mark}</span><span className="text-sm font-medium">{item.title}</span></div><p className="mt-2 text-xs leading-5 text-[#8190a3]">{item.detail}</p></div>)}</div>
          </section>
          <section className="border border-[#1a2937] bg-[#080e15] p-4">
            <div className="font-mono text-[10px] uppercase tracking-[.18em] text-[#b8f37d]">Execution contract</div>
            <h2 className="mt-2 text-base font-semibold">Safe engineering loop</h2>
            <ol className="mt-4 space-y-3">{["Read live state and source code", "Cite evidence and isolate the failure", "Propose a bounded implementation", "Request approval where required", "Apply, test and verify the result"].map((item, i) => <li key={item} className="flex gap-3 text-xs leading-5 text-[#a3b1c0]"><span className="font-mono text-[#b8f37d]">0{i + 1}</span><span>{item}</span></li>)}</ol>
          </section>
          <section className="border border-[#1a2937] bg-[#080e15] p-4">
            <div className="font-mono text-[10px] uppercase tracking-[.18em] text-[#ff8ca0]">Non-negotiable guardrails</div>
            <ul className="mt-3 space-y-3">{guardrails.map((rule) => <li key={rule} className="border-l border-[#ff2d55]/50 pl-3 text-xs leading-5 text-[#a3b1c0]">{rule}</li>)}</ul>
          </section>
        </aside>
      </div>
    </main>
  );
}
