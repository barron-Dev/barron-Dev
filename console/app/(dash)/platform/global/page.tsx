"use client";

import { useEffect, useState } from "react";

type Prefs = { default_locale: string; default_region: string; timezone: string; country: string; alert_languages: string[] };
type Channel = { id: string; platform: string; handle: string; language?: string; countries?: string[]; categories?: string[] };

export default function GlobalSettingsPage() {
  const [prefs, setPrefs] = useState<Prefs | null>(null);
  const [channels, setChannels] = useState<Channel[]>([]);
  const [subs, setSubs] = useState<Set<string>>(new Set());
  const [regulators, setRegulators] = useState<any[]>([]);
  const [certs, setCerts] = useState<any[]>([]);
  const [tab, setTab] = useState<"region" | "channels" | "cert">("region");
  const [message, setMessage] = useState("");

  async function load() {
    const responses = await Promise.all([
      fetch("/api/proxy/v1/catalog/preferences"),
      fetch("/api/proxy/v1/catalog/channels"),
      fetch("/api/proxy/v1/catalog/channels/subscriptions"),
      fetch("/api/proxy/v1/catalog/regulators"),
      fetch("/api/proxy/v1/catalog/certs"),
    ]);
    if (!responses[0].ok) throw new Error("Unable to load global settings");
    setPrefs(await responses[0].json());
    setChannels(responses[1].ok ? await responses[1].json() : []);
    setSubs(new Set(responses[2].ok ? (await responses[2].json()).map((x: any) => x.channel_id) : []));
    setRegulators(responses[3].ok ? await responses[3].json() : []);
    setCerts(responses[4].ok ? await responses[4].json() : []);
  }

  useEffect(() => { load().catch((e) => setMessage(e.message)); }, []);

  async function savePrefs() {
    if (!prefs) return;
    const r = await fetch("/api/proxy/v1/catalog/preferences", {
      method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(prefs),
    });
    setMessage(r.ok ? "Preferences saved." : "Unable to save preferences.");
  }

  async function toggleChannel(id: string) {
    const previous = new Set(subs);
    const next = new Set(subs);
    if (next.has(id)) next.delete(id); else next.add(id);
    setSubs(next);
    const r = await fetch("/api/proxy/v1/catalog/channels/subscribe", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ channel_ids: Array.from(next) }),
    });
    if (!r.ok) { setSubs(previous); setMessage("Channel subscription failed."); }
  }

  return (
    <div className="p-6 space-y-5 max-w-6xl">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Global Settings</h1>
        <p className="text-xs text-text-tertiary mt-1">Region, language, channels, regulators and CERTs are tenant-selected data.</p>
      </header>
      <nav className="flex gap-1 bg-surface border border-border-subtle rounded-lg p-1 w-fit">
        <button onClick={() => setTab("region")} className={tabClass(tab === "region")}>Region</button>
        <button onClick={() => setTab("channels")} className={tabClass(tab === "channels")}>Channels</button>
        <button onClick={() => setTab("cert")} className={tabClass(tab === "cert")}>CERTs &amp; ISACs</button>
      </nav>
      {message && <div className="text-xs text-text-tertiary">{message}</div>}

      {tab === "region" && prefs && (
        <section className="card p-5 space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            <Field label="Country (ISO)"><input value={prefs.country} maxLength={2} onChange={(e) => setPrefs({ ...prefs, country: e.target.value.toUpperCase() })} className="input" /></Field>
            <Field label="Default region"><input value={prefs.default_region} maxLength={2} onChange={(e) => setPrefs({ ...prefs, default_region: e.target.value.toUpperCase() })} className="input" /></Field>
            <Field label="Default locale"><input value={prefs.default_locale} maxLength={10} onChange={(e) => setPrefs({ ...prefs, default_locale: e.target.value })} className="input" /></Field>
            <Field label="Timezone"><input value={prefs.timezone} maxLength={64} onChange={(e) => setPrefs({ ...prefs, timezone: e.target.value })} className="input" /></Field>
          </div>
          <button onClick={savePrefs} className="h-9 px-4 rounded-md bg-accent text-text-inverse text-sm font-medium">Save</button>
          <div className="pt-3 border-t border-border-subtle">
            <div className="panel-title mb-2">Applicable regulators</div>
            <div className="flex flex-wrap gap-2">
              {regulators.filter((r) => r.country === prefs.country).map((r, i) => <span key={i} className="text-xs px-2 py-1 rounded bg-elevated border border-border-subtle">{r.name}</span>)}
            </div>
          </div>
        </section>
      )}

      {tab === "channels" && (
        <section className="card p-5 space-y-3">
          <div className="panel-title">Global monitoring channels</div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
            {channels.map((c) => <button key={c.id} onClick={() => toggleChannel(c.id)} className={channelClass(subs.has(c.id))}>
              <div className="text-sm font-medium">@{c.handle}</div>
              <div className="text-[10px] text-text-tertiary font-mono mt-1">{c.platform} · {c.language || "—"} · {(c.countries || []).join(",") || "global"}</div>
              <div className="text-[10px] text-text-disabled mt-1">{(c.categories || []).join(", ")}</div>
            </button>)}
          </div>
        </section>
      )}

      {tab === "cert" && (
        <section className="card p-5">
          <div className="panel-title mb-3">CERT / CSIRT catalog</div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
            {certs.map((c, i) => <div key={i} className="p-3 rounded-lg bg-inset border border-border-subtle"><div className="text-sm">{c.name}</div><div className="text-[10px] text-text-tertiary font-mono mt-1">{c.country || "global"}</div></div>)}
          </div>
        </section>
      )}
    </div>
  );
}

function tabClass(active: boolean) { return "px-3 py-1 text-xs rounded-md " + (active ? "bg-elevated text-text-primary" : "text-text-tertiary"); }
function channelClass(active: boolean) { return "text-left p-3 rounded-lg border " + (active ? "bg-accent/10 border-accent/40" : "bg-inset border-border-subtle"); }
function Field({ label, children }: { label: string; children: React.ReactNode }) { return <div><label className="panel-title block mb-1.5">{label}</label>{children}</div>; }
