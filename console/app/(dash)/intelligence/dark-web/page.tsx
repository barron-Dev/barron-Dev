"use client";

import { FormEvent, useEffect, useState } from "react";
import { apiFetch } from "../../../../lib/api";
import { ServiceEmpty, ServiceError, ServiceLoading, ServiceSection, ServiceTable } from "../../../../components/ServiceData";

type Row = Record<string, unknown>;
type Watch = Row & { id?: string; kind?: string; value?: string; label?: string; severity?: string };
type Alert = Row & { id?: string; title?: string; severity?: string; status?: string; finding_id?: string; case_id?: string | null };

const inputClass = "w-full border border-[#1a2330] bg-[#090c11] px-3 py-2 text-xs text-[#e8eef6] outline-none focus:border-[#40556f]";
const buttonClass = "border border-[#2a394d] bg-[#0b1118] px-3 py-2 text-[10px] uppercase tracking-[.12em] text-[#d7e1ec] disabled:cursor-not-allowed disabled:opacity-40";

const watchKinds = ["email", "domain", "ip", "wallet", "phone", "company_name", "executive_name", "api_key_hash", "employee_id", "customer_id"];
const statuses = ["new", "acknowledged", "investigating", "remediated", "false_positive"];

export default function DarkWeb() {
  const [watchlist, setWatchlist] = useState<Watch[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stats, setStats] = useState<Row | null>(null);
  const [findings, setFindings] = useState<Row[]>([]);
  const [sources, setSources] = useState<Row[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [kind, setKind] = useState("domain");
  const [value, setValue] = useState("");
  const [label, setLabel] = useState("");
  const [severity, setSeverity] = useState("high");
  const [alertStatus, setAlertStatus] = useState("acknowledged");

  async function load() {
    setLoading(true);
    setError("");
    try {
      const [w, a, s, f, src] = await Promise.all([
        apiFetch<Watch[]>("/api/v1/darkweb/watchlist"),
        apiFetch<Alert[]>("/api/v1/darkweb/alerts"),
        apiFetch<Row>("/api/v1/darkweb/stats"),
        apiFetch<Row[]>("/api/v1/darkweb/findings"),
        apiFetch<Row[]>("/api/v1/darkweb/sources"),
      ]);
      setWatchlist(Array.isArray(w) ? w : []);
      setAlerts(Array.isArray(a) ? a : []);
      setStats(s ?? null);
      setFindings(Array.isArray(f) ? f : []);
      setSources(Array.isArray(src) ? src : []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load dark web intelligence");
    } finally { setLoading(false); }
  }

  useEffect(() => { void load(); }, []);

  async function addWatch(e: FormEvent) {
    e.preventDefault();
    setBusy("add-watch"); setError(""); setNotice("");
    try {
      await apiFetch("/api/v1/darkweb/watchlist", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ kind, value: value.trim(), label: label.trim() || null, severity }),
      });
      setValue(""); setLabel(""); setNotice("Watch target added.");
      await load();
    } catch (e) { setError(e instanceof Error ? e.message : "Could not add watch target"); }
    finally { setBusy(""); }
  }

  async function deleteWatch(id: string) {
    setBusy("delete:" + id); setError(""); setNotice("");
    try {
      await apiFetch("/api/v1/darkweb/watchlist/" + encodeURIComponent(id), { method: "DELETE" });
      setNotice("Watch target removed.");
      await load();
    } catch (e) { setError(e instanceof Error ? e.message : "Could not remove watch target"); }
    finally { setBusy(""); }
  }

  async function updateAlert(id: string, status: string) {
    setBusy("alert:" + id); setError(""); setNotice("");
    try {
      await apiFetch("/api/v1/darkweb/alerts/" + encodeURIComponent(id), {
        method: "PATCH", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status }),
      });
      setNotice("Alert status updated.");
      await load();
    } catch (e) { setError(e instanceof Error ? e.message : "Could not update alert"); }
    finally { setBusy(""); }
  }

  async function openCase(id: string) {
    setBusy("case:" + id); setError(""); setNotice("");
    try {
      const result = await apiFetch<{ case_id?: string }>("/api/v1/darkweb/alerts/" + encodeURIComponent(id) + "/open-case", { method: "POST" });
      setNotice(result.case_id ? "Case opened: " + result.case_id : "Case opened.");
      await load();
    } catch (e) { setError(e instanceof Error ? e.message : "Could not open case"); }
    finally { setBusy(""); }
  }

  return (
    <main className="min-h-screen bg-[#05070a] p-6 text-[#e8eef6]">
      <div className="mx-auto max-w-7xl space-y-5">
        <header>
          <div className="text-[10px] uppercase tracking-[.16em] text-[#5a6675]">Intelligence</div>
          <h1 className="mt-1 text-2xl font-semibold">Dark Web Intelligence</h1>
          <p className="mt-1 text-xs text-[#8a97a8]">Manage watch targets, inspect findings and operate tenant alerts from live dark-web data.</p>
        </header>

        {error && <ServiceError message={error} />}
        {notice && <div className="border border-[#26384a] bg-[#091018] px-4 py-3 text-xs text-[#b9c9d9]">{notice}</div>}

        {loading ? <ServiceLoading /> : (
          <>
            <div className="grid gap-4 lg:grid-cols-3">
              <ServiceSection title="Alert summary">
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                  {["total_alerts", "new", "critical", "high", "remediated"].map(key => (
                    <div key={key} className="border border-[#1a2330] bg-[#05070a] p-3">
                      <div className="text-[9px] uppercase tracking-[.12em] text-[#5a6675]">{key.replace("_", " ")}</div>
                      <div className="mt-2 font-mono text-xl">{String(stats?.[key] ?? 0)}</div>
                    </div>
                  ))}
                </div>
              </ServiceSection>

              <ServiceSection title="Add watch target">
                <form onSubmit={addWatch} className="space-y-2">
                  <select className={inputClass} value={kind} onChange={e => setKind(e.target.value)}>
                    {watchKinds.map(k => <option key={k} value={k}>{k}</option>)}
                  </select>
                  <input className={inputClass} value={value} onChange={e => setValue(e.target.value)} placeholder="Value to monitor" required />
                  <input className={inputClass} value={label} onChange={e => setLabel(e.target.value)} placeholder="Label (optional)" />
                  <select className={inputClass} value={severity} onChange={e => setSeverity(e.target.value)}>
                    <option value="medium">medium</option><option value="high">high</option><option value="critical">critical</option>
                  </select>
                  <button className={buttonClass} disabled={busy === "add-watch"}>{busy === "add-watch" ? "Adding..." : "Add watch target"}</button>
                </form>
              </ServiceSection>

              <ServiceSection title="Alert operation">
                <select className={inputClass} value={alertStatus} onChange={e => setAlertStatus(e.target.value)}>
                  {statuses.map(s => <option key={s} value={s}>{s}</option>)}
                </select>
                <p className="mt-2 text-[10px] text-[#687789]">Select the target status, then use the action on an alert below.</p>
              </ServiceSection>
            </div>

            <ServiceSection title="Watchlist" count={watchlist.length}>
              <ServiceTable rows={watchlist} columns={[
                { key: "kind", label: "Kind" }, { key: "value", label: "Value" },
                { key: "label", label: "Label" }, { key: "severity", label: "Severity" },
                { key: "created_at", label: "Created" },
              ]} empty={<ServiceEmpty title="No watchlist entries" detail="No tenant watch targets are configured." />} />
              {watchlist.length > 0 && <div className="mt-3 flex flex-wrap gap-2">
                {watchlist.map(w => <button key={String(w.id)} className={buttonClass} disabled={!!busy} onClick={() => void deleteWatch(String(w.id))}>Remove {String(w.value ?? w.id)}</button>)}
              </div>}
            </ServiceSection>

            <ServiceSection title="Sources" count={sources.length}>
              <ServiceTable rows={sources} columns={[
                { key: "name", label: "Source" }, { key: "kind", label: "Kind" },
                { key: "enabled", label: "Enabled" }, { key: "last_status", label: "Last status" },
                { key: "last_pull_at", label: "Last pull" },
              ]} empty={<ServiceEmpty title="No sources" detail="No dark-web sources are configured." />} />
            </ServiceSection>

            <ServiceSection title="Findings" count={findings.length}>
              <ServiceTable rows={findings} columns={[
                { key: "kind", label: "Kind" }, { key: "matched_value", label: "Match" },
                { key: "severity", label: "Severity" }, { key: "source_id", label: "Source" },
                { key: "first_seen", label: "First seen" },
              ]} empty={<ServiceEmpty title="No findings" detail="No findings are returned for this tenant." />} />
            </ServiceSection>

            <ServiceSection title="Alerts" count={alerts.length}>
              <ServiceTable rows={alerts} columns={[
                { key: "title", label: "Alert" }, { key: "severity", label: "Severity" },
                { key: "status", label: "Status" }, { key: "finding_id", label: "Finding" },
                { key: "created_at", label: "Created" },
              ]} empty={<ServiceEmpty title="No alerts" detail="No tenant alerts are currently recorded." />} />
              {alerts.length > 0 && <div className="mt-3 space-y-2">
                {alerts.map(a => (
                  <div key={String(a.id)} className="flex flex-wrap items-center gap-2 border border-[#141d28] bg-[#080b10] p-3">
                    <span className="mr-auto text-xs text-[#aebbc9]">{String(a.title ?? a.id)} · {String(a.severity ?? "unknown")} · {String(a.status ?? "unknown")}</span>
                    <button className={buttonClass} disabled={!!busy} onClick={() => void updateAlert(String(a.id), alertStatus)}>{busy === "alert:" + a.id ? "Updating..." : "Set status"}</button>
                    <button className={buttonClass} disabled={!!busy || !!a.case_id} onClick={() => void openCase(String(a.id))}>{a.case_id ? "Case opened" : "Open case"}</button>
                  </div>
                ))}
              </div>}
            </ServiceSection>
          </>
        )}
      </div>
    </main>
  );
}
