"use client";

import { useEffect, useMemo, useState } from "react";
import { getOverview, ConsoleOverview, setApiToken } from "../../../lib/api";
import { Panel } from "@/components/design/Panel";
import { C } from "@/lib/design/tokens";

export default function CustomerOverview() {
  const [data, setData] = useState<ConsoleOverview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [token, setToken] = useState("");
  const [query, setQuery] = useState("");

  async function load() {
    try {
      setData(await getOverview());
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to reach Cyclothone API");
    }
  }

  useEffect(() => {
    const saved = sessionStorage.getItem("cyclothone_access_token") ?? "";
    setToken(saved);
    setApiToken(saved);
    void load();
  }, []);

  const feed = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return data?.feed ?? [];
    return (data?.feed ?? []).filter(x =>
      [x.detector, x.verdict, x.device_id, ...(x.reasons ?? []), x.mitre_technique]
        .some(v => (v ?? "").toLowerCase().includes(q))
    );
  }, [data, query]);

  return (
    <main className="min-h-screen bg-[#05070a] text-[#e8eef6]">
      <header className="flex h-14 items-center justify-between border-b border-[#1a2330] bg-[#0a0e14] px-4">
        <div className="flex items-center gap-3">
          <a href="https://cyclothone.online" className="font-semibold tracking-tight">Cyclothone</a>
          <span className="font-mono text-[10px] text-[#ffb347]">/customer</span>
        </div>
        <div className="flex gap-2">
          <a href="/customer/workspace" className="border border-[#ffb347]/50 px-3 py-1.5 text-[10px] text-[#ffb347]">Workspace</a>
          <a href="/customer/cases" className="border border-[#2a3646] px-3 py-1.5 text-[10px]">Cases</a>
          <a href="/request-service" className="border border-[#00d9ff] px-3 py-1.5 text-[10px] text-[#00d9ff]">Request service</a>
        </div>
      </header>

      <div className="flex min-h-[calc(100vh-56px)]">
        <aside className="hidden w-60 shrink-0 border-r border-[#1a2330] bg-[#0a0e14] p-4 md:block">
          <div className="mb-5 text-[9px] font-semibold uppercase tracking-[.16em] text-[#5a6675]">Customer operations</div>
          {[
            ["Overview", "/customer/overview"],
            ["Workspace", "/customer/workspace"],
            ["Cases", "/customer/cases"],
            ["Request service", "/request-service"],
          ].map(([label, href]) => (
            <a key={label} href={href} className="mb-1 flex h-8 items-center rounded border-l-2 border-transparent px-3 text-[12px] text-[#8a97a8] hover:bg-[#111823]">
              {label}
            </a>
          ))}
          <div className="mb-2 mt-7 text-[9px] font-semibold uppercase tracking-[.16em] text-[#5a6675]">Platform</div>
          <a href="https://developers.cyclothone.online" className="flex h-8 items-center px-3 text-[12px] text-[#8a97a8] hover:bg-[#111823]">Developer platform</a>
          <div className="mt-8 border-t border-[#1a2330] pt-4 text-[9px] text-[#5a6675]">
            Public Surface remains separate from customer operations.
          </div>
        </aside>

        <section className="min-w-0 flex-1 overflow-auto">
          <div className="border-b border-[#1a2330] px-6 py-5">
            <div className="text-[10px] uppercase tracking-[.16em] text-[#5a6675]">Customer operational surface</div>
            <h1 className="mt-1 text-2xl font-semibold">Security Overview</h1>
            <p className="mt-1 max-w-2xl text-[11px] text-[#8a97a8]">
              Live operational data exposed by the authorized customer API. No synthetic tenant or security records are displayed.
            </p>
          </div>

          <div className="grid grid-cols-2 border-b border-[#1a2330] md:grid-cols-4">
            {[
              ["Agents", data?.agents.total.toLocaleString() ?? "—", "registered devices"],
              ["Threats", data?.threats.last_24h.toLocaleString() ?? "—", "last 24h"],
              ["Critical cases", data?.critical.count.toLocaleString() ?? "—", "last 24h"],
              ["API uptime", data?.uptime_percent == null ? "—" : data.uptime_percent + "%", "current telemetry"],
            ].map(([label, value, meta]) => (
              <div key={label} className="border-r border-[#1a2330] px-5 py-6 last:border-0">
                <div className="font-mono text-2xl font-bold">{value}</div>
                <div className="mt-2 text-[10px] uppercase tracking-[.12em] text-[#5a6675]">{label}</div>
                <div className="mt-1 font-mono text-[10px] text-[#8a97a8]">{meta}</div>
              </div>
            ))}
          </div>

          {error && (
            <div className="mx-6 mt-5 border border-[#ff2d55]/40 bg-[#ff2d55]/5 p-4">
              <div className="text-[11px] text-[#ff6b83]">Failed to fetch live customer telemetry.</div>
              <div className="mt-3 flex gap-2">
                <input value={token} onChange={e => setToken(e.target.value)} type="password" placeholder="Access token (memory only)" className="w-72 border border-[#2a3646] bg-[#030508] px-2 py-1.5 font-mono text-[10px]" />
                <button onClick={() => { setApiToken(token); void load(); }} className="border border-[#00d9ff] px-3 py-1.5 text-[10px] text-[#00d9ff]">Connect</button>
              </div>
            </div>
          )}

          <div className="grid gap-4 p-6 lg:grid-cols-2">
            <Panel glow accent={C.customerAccent}>
              <div className="flex items-center justify-between">
                <div className="type-h2">Live threat feed</div>
                <span className="type-code text-[#5a6675]">API snapshot</span>
              </div>
              <div className="mt-4 divide-y divide-[#1a2330]">
                {feed.length ? feed.slice(0, 20).map(r => (
                  <div key={r.id} className="flex items-center justify-between gap-3 py-2.5">
                    <div className="min-w-0">
                      <div className="font-mono text-[10px] text-[#5a6675]">{r.id.slice(0, 8)}</div>
                      <div className="truncate text-[11px]">{r.detector}</div>
                    </div>
                    <span className="font-mono text-[9px] uppercase text-[#8a97a8]">{r.verdict ?? "unknown"}</span>
                  </div>
                )) : <div className="py-8 text-center text-[11px] text-[#5a6675]">No detections returned by the API.</div>}
              </div>
            </Panel>

            <Panel>
              <div className="type-h2">Trust architecture</div>
              <p className="mt-2 text-[11px] leading-5 text-[#8a97a8]">
                Cyclothone keeps identity, evidence, authorization, execution authority, and provenance outside the AI model.
              </p>
              <div className="mt-5 grid gap-2 sm:grid-cols-2">
                {[
                  ["Identity", "Versioned workload identity"],
                  ["Envelope", "Signed execution authority"],
                  ["Mission", "Hash-bound execution plan"],
                  ["Provenance", "Durable execution evidence"],
                ].map(([title, description]) => (
                  <div key={title} className="border border-[#1a2330] p-3">
                    <div className="text-[11px] font-medium">{title}</div>
                    <div className="mt-1 text-[10px] text-[#5a6675]">{description}</div>
                  </div>
                ))}
              </div>
            </Panel>

            <Panel>
              <div className="mb-3 flex items-center justify-between">
                <span className="type-h2">Detection activity</span>
                <span className="font-mono text-[10px] text-[#5a6675]">{feed.length} matching rows</span>
              </div>
              <input value={query} onChange={e => setQuery(e.target.value)} placeholder="Filter returned detections…" className="w-full border border-[#2a3646] bg-[#030508] px-3 py-2 text-[11px]" />
            </Panel>

            <Panel>
              <div className="type-h2">Customer entry points</div>
              <div className="mt-4 flex flex-wrap gap-2">
                <a href="/customer/workspace" className="border border-[#ffb347]/50 px-3 py-2 text-[10px] text-[#ffb347]">Open workspace</a>
                <a href="/customer/cases" className="border border-[#2a3646] px-3 py-2 text-[10px]">View cases</a>
                <a href="/request-service" className="border border-[#00d9ff]/50 px-3 py-2 text-[10px] text-[#00d9ff]">Request security service</a>
              </div>
            </Panel>
          </div>
        </section>
      </div>
    </main>
  );
}
