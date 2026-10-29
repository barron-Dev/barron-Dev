"use client";

import { FormEvent, useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";
import { AuthActions } from "@/components/AuthActions";

type Watch = { id: string; kind: string; value: string; label?: string | null; severity?: string; created_at?: string };
type Source = { id: string; name: string; enabled: boolean; last_status?: string | null; last_pull_at?: string | null; web_layer?: string; access_mode?: string };
type Finding = { id: string; source_id?: string; matched_value?: string; kind?: string; severity?: string; source_url?: string; web_layer?: string; collected_at?: string; first_seen?: string };

const kinds = ["email", "domain", "ip", "wallet", "phone", "company_name", "executive_name", "api_key_hash", "employee_id", "customer_id"];
const panel = "border border-white/10 bg-[#071019]/85 p-5";
const input = "w-full border border-white/10 bg-[#030a10] px-3 py-3 text-sm outline-none focus:border-[#c2f35a]/60";
const button = "rounded-full border border-[#c2f35a]/50 bg-[#c2f35a]/10 px-4 py-2 text-xs font-medium text-[#ddff9a] disabled:opacity-40";

function recent(timestamp?: string | null) {
  if (!timestamp) return false;
  const time = Date.parse(timestamp);
  return Number.isFinite(time) && time >= Date.now() - 24 * 60 * 60 * 1000;
}

export default function DeveloperDarkWeb() {
  const [watchlist, setWatchlist] = useState<Watch[]>([]);
  const [sources, setSources] = useState<Source[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [kind, setKind] = useState("domain");
  const [value, setValue] = useState("");
  const [severity, setSeverity] = useState("high");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  async function load() {
    setLoading(true);
    setError("");
    try {
      const [w, s, f] = await Promise.all([
        apiFetch<Watch[]>("/api/v1/darkweb/watchlist"),
        apiFetch<Source[]>("/api/v1/darkweb/sources"),
        apiFetch<Finding[]>("/api/v1/darkweb/findings?limit=100"),
      ]);
      setWatchlist(Array.isArray(w) ? w : []);
      setSources(Array.isArray(s) ? s : []);
      setFindings(Array.isArray(f) ? f : []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Dark Web API request failed");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void load(); }, []);

  async function addTarget(event: FormEvent) {
    event.preventDefault();
    if (!value.trim()) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await apiFetch<Watch>("/api/v1/darkweb/watchlist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ kind, value: value.trim(), severity }),
      });
      setValue("");
      setNotice("Target saved. This confirms watchlist persistence only; it does not confirm a scan or source attempt.");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not save target");
    } finally {
      setBusy(false);
    }
  }

  async function removeTarget(id: string) {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await apiFetch<void>("/api/v1/darkweb/watchlist/" + encodeURIComponent(id), { method: "DELETE" });
      setNotice("Target removed from the watchlist.");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not remove target");
    } finally {
      setBusy(false);
    }
  }

  const supportedSurface = sources.filter((s) => ["telegram_public", "pastebin_public", "bluesky_public", "native_onion"].includes(s.id));
  const freshSources = supportedSurface.filter((s) => s.enabled && s.last_status === "ok" && recent(s.last_pull_at));
  const coverage = supportedSurface.length > 0 && freshSources.length === supportedSurface.filter((s) => s.enabled).length && supportedSurface.some((s) => s.enabled)
    ? "Enabled sources have recent successful pulls"
    : "Coverage incomplete — recent source attempts are not proven";

  return (
    <main className="cyclo-water min-h-screen text-[#e8eef6]">
      <header className="border-b border-white/10 bg-[#02090e]/70 px-5 py-4 backdrop-blur-2xl">
        <div className="mx-auto flex max-w-6xl items-center justify-between gap-4">
          <div><span className="cyclo-mark font-semibold">◌ CYCLOTHONE</span><span className="ml-3 text-[10px] uppercase tracking-[.16em] text-[#c2f35a]">Developer</span></div>
          <AuthActions />
        </div>
      </header>
      <div className="mx-auto max-w-6xl space-y-6 px-5 py-8 md:px-8">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="text-[10px] uppercase tracking-[.18em] text-[#c2f35a]">API workspace · Dark Web Monitoring</p>
            <h1 className="mt-2 text-2xl font-semibold">Developer Dark Web</h1>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-[#8a97a8]">Inspect the authenticated Dark Web API, manage watch targets, and review source freshness and returned findings. No simulated results are shown.</p>
          </div>
          <a href="/developers" className="border border-white/15 px-4 py-2 text-xs text-[#c6d2df] hover:border-white/30">Developer access →</a>
        </div>

        <div className="grid gap-3 sm:grid-cols-3">
          <div className={panel}><div className="text-xs text-[#8a97a8]">Watch targets</div><div className="mt-2 text-2xl">{loading ? "—" : watchlist.length}</div><div className="mt-1 text-[10px] text-[#657487]">Authenticated API response</div></div>
          <div className={panel}><div className="text-xs text-[#8a97a8]">Returned findings</div><div className="mt-2 text-2xl">{loading ? "—" : findings.length}</div><div className="mt-1 text-[10px] text-[#657487]">Most recent API page, max 100</div></div>
          <div className={panel}><div className="text-xs text-[#8a97a8]">Source coverage</div><div className="mt-2 text-sm font-medium text-[#ffbd78]">{loading ? "Checking…" : coverage}</div><div className="mt-1 text-[10px] text-[#657487]">Configuration is not proof of collection</div></div>
        </div>

        {error && <div role="alert" className="border border-[#713744] bg-[#1a0b11] p-4 text-sm text-[#ffb5c2]">{error}<p className="mt-2 text-xs text-[#c18b97]">If the API backend is unavailable, this workspace cannot verify live state. Retry after the API is restored; no fallback data is substituted.</p></div>}
        {notice && <div role="status" className="border border-[#244936] bg-[#07140d] p-4 text-sm text-[#bce8c9]">{notice}</div>}

        <section className={panel}>
          <h2 className="text-sm font-semibold">Create a watch target</h2>
          <p className="mt-1 text-xs leading-5 text-[#7e8da0]">Requires the authenticated identity to hold the <code>darkweb:manage</code> scope.</p>
          <form onSubmit={addTarget} className="mt-4 grid gap-3 md:grid-cols-[.8fr_1.6fr_.8fr_auto]">
            <select className={input} value={kind} onChange={(e) => setKind(e.target.value)}>{kinds.map((k) => <option key={k} value={k}>{k.replaceAll("_", " ")}</option>)}</select>
            <input className={input} value={value} onChange={(e) => setValue(e.target.value)} placeholder="Target value" required minLength={2} maxLength={512} />
            <select className={input} value={severity} onChange={(e) => setSeverity(e.target.value)}><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></select>
            <button className={button} disabled={busy || loading}>{busy ? "Working…" : "Save target"}</button>
          </form>
        </section>

        <section className={panel}>
          <div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="text-sm font-semibold">Watchlist</h2><p className="mt-1 text-xs text-[#7e8da0]">Tenant-scoped records returned by the live API.</p></div><button className={button} onClick={() => void load()} disabled={loading || busy}>Refresh</button></div>
          {loading ? <p className="mt-4 text-sm text-[#7e8da0]">Loading from API…</p> : watchlist.length === 0 ? <p className="mt-4 border border-white/10 p-4 text-sm text-[#8a97a8]">No targets returned. This is not evidence that monitoring is clean.</p> : <div className="mt-4 divide-y divide-white/10">{watchlist.map((w) => <div key={w.id} className="flex flex-wrap items-center gap-3 py-3"><div className="mr-auto min-w-0"><div className="break-all text-sm">{w.value}</div><div className="mt-1 text-[10px] text-[#7e8da0]">{w.kind} · {w.severity ?? "unspecified"} · {w.created_at ? new Date(w.created_at).toLocaleString() : "creation time unavailable"}</div></div><button className="border border-white/15 px-3 py-2 text-[10px] text-[#d3dce6] disabled:opacity-40" disabled={busy} onClick={() => void removeTarget(w.id)}>Remove</button></div>)}</div>}
        </section>

        <section className={panel}>
          <h2 className="text-sm font-semibold">Source status</h2>
          <p className="mt-1 text-xs text-[#7e8da0]">Current source configuration and last recorded pull timestamps. The API does not expose per-request worker leases here.</p>
          {loading ? <p className="mt-4 text-sm text-[#7e8da0]">Loading source state…</p> : <div className="mt-4 space-y-2">{supportedSurface.map((s) => <div key={s.id} className="grid gap-2 border border-white/10 p-3 sm:grid-cols-[1.1fr_.7fr_1fr_1fr]"><div className="text-xs">{s.name}</div><div className="text-xs text-[#9baabc]">{s.enabled ? "Enabled in config" : "Disabled"}</div><div className="text-xs text-[#9baabc]">{s.last_status ?? "No recorded status"}</div><div className="text-xs text-[#9baabc]">{s.last_pull_at ? new Date(s.last_pull_at).toLocaleString() : "Never recorded"}</div></div>)}</div>}
        </section>

        <section className={panel}>
          <h2 className="text-sm font-semibold">Latest findings</h2>
          <p className="mt-1 text-xs text-[#7e8da0]">Findings returned by the tenant-scoped endpoint. A zero-row response is not a clean result when collection is stale or unavailable.</p>
          {loading ? <p className="mt-4 text-sm text-[#7e8da0]">Loading findings…</p> : findings.length === 0 ? <p className="mt-4 border border-white/10 p-4 text-sm text-[#8a97a8]">No findings returned by this request.</p> : <div className="mt-4 space-y-2">{findings.map((f) => <div key={f.id} className="border border-white/10 p-3"><div className="flex flex-wrap justify-between gap-2"><span className="break-all text-xs">{f.matched_value ?? f.kind ?? "Finding"}</span><span className="text-[10px] uppercase text-[#ffbd78]">{f.severity ?? "severity unavailable"}</span></div><div className="mt-1 text-[10px] text-[#7e8da0]">{f.source_id ?? "Unknown source"} · {f.web_layer ?? "layer unavailable"} · {f.collected_at ? new Date(f.collected_at).toLocaleString() : "collection time unavailable"}</div>{f.source_url && <a className="mt-2 inline-block break-all text-[10px] text-[#83d9f0] underline" href={f.source_url} target="_blank" rel="noreferrer">Open source evidence</a>}</div>)}</div>}
        </section>

        <section className="border border-[#c2f35a]/20 bg-[#071019]/60 p-5">
          <h2 className="text-sm font-semibold">API contract</h2>
          <p className="mt-1 text-xs leading-5 text-[#8a97a8]">The workspace calls the existing authenticated API. These endpoints require <code>darkweb:read</code> for reads and <code>darkweb:manage</code> for watchlist writes.</p>
          <div className="mt-3 grid gap-2 text-xs sm:grid-cols-2">
            <code className="border border-white/10 p-3">GET /api/v1/darkweb/watchlist</code>
            <code className="border border-white/10 p-3">POST /api/v1/darkweb/watchlist</code>
            <code className="border border-white/10 p-3">GET /api/v1/darkweb/sources</code>
            <code className="border border-white/10 p-3">GET /api/v1/darkweb/findings?limit=100</code>
          </div>
          <p className="mt-3 text-xs leading-5 text-[#8a97a8]">The current API confirms watchlist persistence but does not return a worker execution receipt. Monitoring activation and source-attempt evidence remain a separate backend release gate.</p>
        </section>
      </div>
    </main>
  );
}
