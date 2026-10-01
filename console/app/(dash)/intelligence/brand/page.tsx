"use client";

import { FormEvent, useEffect, useState } from "react";
import { apiFetch } from "../../../../lib/api";
import { ServiceEmpty, ServiceError, ServiceLoading, ServiceSection, ServiceTable } from "../../../../components/ServiceData";

type Row = Record<string, unknown>;
type Brand = Row & { id?: string; name?: string; primary_domain?: string };
type Threat = Row & { id?: string; kind?: string; severity?: string; status?: string };

const inputClass = "w-full border border-[#1a2330] bg-[#090c11] px-3 py-2 text-xs text-[#e8eef6] outline-none focus:border-[#40556f]";
const buttonClass = "border border-[#2a394d] bg-[#0b1118] px-3 py-2 text-[10px] uppercase tracking-[.12em] text-[#d7e1ec] disabled:cursor-not-allowed disabled:opacity-40";

export default function BrandPage() {
  const [brands, setBrands] = useState<Brand[]>([]);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [stats, setStats] = useState<Row | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [name, setName] = useState("");
  const [domain, setDomain] = useState("");
  const [similarity, setSimilarity] = useState("0.75");
  const [selectedBrand, setSelectedBrand] = useState("");
  const [provider, setProvider] = useState("");

  async function load() {
    setLoading(true);
    setError("");
    try {
      const [b, t, s] = await Promise.all([
        apiFetch<Brand[]>("/api/v1/brand/brands"),
        apiFetch<Threat[]>("/api/v1/brand/threats?limit=200"),
        apiFetch<Row>("/api/v1/brand/stats"),
      ]);
      setBrands(Array.isArray(b) ? b : []);
      setThreats(Array.isArray(t) ? t : []);
      setStats(s ?? null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load brand intelligence");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void load(); }, []);

  async function createBrand(e: FormEvent) {
    e.preventDefault();
    setBusy("create");
    setError("");
    setNotice("");
    try {
      await apiFetch("/api/v1/brand/brands", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: name.trim(), primary_domain: domain.trim(), similarity_min: Number(similarity) }),
      });
      setName("");
      setDomain("");
      setNotice("Protected brand created.");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Brand creation failed");
    } finally { setBusy(""); }
  }

  async function scanBrand(id: string) {
    setBusy(`scan:${id}`);
    setError("");
    setNotice("");
    try {
      await apiFetch(`/api/v1/brand/brands/${encodeURIComponent(id)}/scan-typosquat`, { method: "POST" });
      setNotice("Typosquat scan completed.");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Typosquat scan failed");
    } finally { setBusy(""); }
  }

  async function updateThreat(id: string, status: string) {
    setBusy(`status:${id}`);
    setError("");
    setNotice("");
    try {
      await apiFetch(`/api/v1/brand/threats/${encodeURIComponent(id)}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status }),
      });
      setNotice("Threat status updated.");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Threat update failed");
    } finally { setBusy(""); }
  }

  async function requestTakedown(id: string) {
    if (!provider.trim()) {
      setError("Enter the takedown provider before requesting a takedown.");
      return;
    }
    setBusy(`takedown:${id}`);
    setError("");
    setNotice("");
    try {
      await apiFetch(`/api/v1/brand/threats/${encodeURIComponent(id)}/takedown`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider: provider.trim() }),
      });
      setNotice("Takedown request submitted.");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Takedown request failed");
    } finally { setBusy(""); }
  }

  const selected = brands.find(b => String(b.id ?? "") === selectedBrand);

  return (
    <main className="min-h-screen bg-[#05070a] p-6 text-[#e8eef6]">
      <div className="mx-auto max-w-7xl space-y-5">
        <header>
          <div className="text-[10px] uppercase tracking-[.16em] text-[#5a6675]">Intelligence</div>
          <h1 className="mt-1 text-2xl font-semibold">Brand Protection</h1>
          <p className="mt-1 text-xs text-[#8a97a8]">Protect registered brands, scan for typosquatting, manage detected threats and submit takedown requests.</p>
        </header>

        {error && <ServiceError message={error} />}
        {notice && <div className="border border-[#26384a] bg-[#091018] px-4 py-3 text-xs text-[#b9c9d9]">{notice}</div>}

        {loading ? <ServiceLoading /> : (
          <>
            <div className="grid gap-4 lg:grid-cols-3">
              <ServiceSection title="Threat summary">
                <div className="grid grid-cols-2 gap-3">
                  {["total", "active", "by_kind", "by_severity"].map(key => (
                    <div key={key} className="border border-[#1a2330] bg-[#05070a] p-4">
                      <div className="text-[9px] uppercase tracking-[.12em] text-[#5a6675]">{key.replaceAll("_", " ")}</div>
                      <div className="mt-2 font-mono text-sm">{typeof stats?.[key] === "object" ? JSON.stringify(stats?.[key]) : String(stats?.[key] ?? 0)}</div>
                    </div>
                  ))}
                </div>
              </ServiceSection>

              <ServiceSection title="Register protected brand">
                <form onSubmit={createBrand} className="space-y-3">
                  <input className={inputClass} value={name} onChange={e => setName(e.target.value)} placeholder="Brand name" required />
                  <input className={inputClass} value={domain} onChange={e => setDomain(e.target.value)} placeholder="primary-domain.example" required />
                  <input className={inputClass} value={similarity} onChange={e => setSimilarity(e.target.value)} type="number" min="0.5" max="0.99" step="0.01" placeholder="Similarity threshold" required />
                  <button className={buttonClass} disabled={busy === "create"}>{busy === "create" ? "Creating..." : "Register brand"}</button>
                </form>
              </ServiceSection>

              <ServiceSection title="Typosquat scanner">
                <select className={inputClass} value={selectedBrand} onChange={e => setSelectedBrand(e.target.value)}>
                  <option value="">Select protected brand</option>
                  {brands.map(b => <option key={String(b.id)} value={String(b.id)}>{String(b.name ?? b.id)}</option>)}
                </select>
                <button className={buttonClass + " mt-3"} disabled={!selected?.id || !!busy} onClick={() => selected?.id && void scanBrand(String(selected.id))}>
                  {busy === `scan:${selectedBrand}` ? "Scanning..." : "Run typosquat scan"}
                </button>
              </ServiceSection>
            </div>

            <ServiceSection title="Protected brands" count={brands.length}>
              <ServiceTable rows={brands} columns={[
                { key: "name", label: "Brand" },
                { key: "primary_domain", label: "Primary domain" },
                { key: "similarity_min", label: "Similarity threshold" },
                { key: "created_at", label: "Created" },
              ]} empty={<ServiceEmpty title="No protected brands" detail="Register a tenant brand above to enable protection workflows." />} />
            </ServiceSection>

            <ServiceSection title="Threat operations">
              <div className="mb-3 flex flex-col gap-2 sm:flex-row">
                <input className={inputClass} value={provider} onChange={e => setProvider(e.target.value)} placeholder="Takedown provider (required for request)" />
              </div>
              <ServiceTable rows={threats} columns={[
                { key: "kind", label: "Kind" },
                { key: "severity", label: "Severity" },
                { key: "status", label: "Status" },
                { key: "first_seen", label: "First seen" },
                { key: "last_seen", label: "Last seen" },
              ]} empty={<ServiceEmpty title="No brand threats" detail="No detected brand threats are currently recorded for this tenant." />}
              />
              {threats.length > 0 && (
                <div className="mt-3 space-y-2">
                  {threats.map(t => (
                    <div key={String(t.id)} className="flex flex-wrap items-center gap-2 border border-[#141d28] bg-[#080b10] p-3">
                      <span className="mr-auto text-xs text-[#aebbc9]">{String(t.kind ?? "threat")} · {String(t.severity ?? "unknown")} · {String(t.status ?? "unknown")}</span>
                      <button className={buttonClass} disabled={!!busy} onClick={() => void updateThreat(String(t.id), "investigating")}>Investigate</button>
                      <button className={buttonClass} disabled={!!busy} onClick={() => void updateThreat(String(t.id), "false_positive")}>False positive</button>
                      <button className={buttonClass} disabled={!!busy} onClick={() => void requestTakedown(String(t.id))}>Request takedown</button>
                    </div>
                  ))}
                </div>
              )}
            </ServiceSection>
          </>
        )}
      </div>
    </main>
  );
}
