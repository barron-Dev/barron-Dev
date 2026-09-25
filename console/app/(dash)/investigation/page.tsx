"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "../../../lib/api";
import { ServiceEmpty, ServiceError, ServiceLoading, ServiceSection, ServiceTable } from "../../../components/ServiceData";

type Investigation = {
  id: string;
  case_id?: string | null;
  purpose?: string;
  authorization_ref?: string;
  status?: string;
  provider?: string;
  provider_session_id?: string | null;
  started_at?: string | null;
  completed_at?: string | null;
  created_at?: string;
  updated_at?: string;
};

type InvestigationDetail = {
  session: Investigation;
  evidence: Record<string, unknown>[];
  events: Record<string, unknown>[];
};

function fmt(value?: string | null) {
  if (!value) return "—";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString();
}

export default function InvestigationPage() {
  const [items, setItems] = useState<Investigation[]>([]);
  const [selected, setSelected] = useState<InvestigationDetail | null>(null);
  const [purpose, setPurpose] = useState("");
  const [authorizationRef, setAuthorizationRef] = useState("");
  const [provider, setProvider] = useState("");
  const [caseId, setCaseId] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");

  async function load() {
    setLoading(true);
    setError("");
    try {
      const result = await apiFetch<{ items: Investigation[]; total: number }>("/api/v1/investigations");
      setItems(Array.isArray(result.items) ? result.items : []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load investigations");
    } finally {
      setLoading(false);
    }
  }

  async function loadDetail(id: string) {
    setBusy(`detail:${id}`);
    setError("");
    try {
      setSelected(await apiFetch<InvestigationDetail>(`/api/v1/investigations/${encodeURIComponent(id)}`));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load investigation detail");
    } finally {
      setBusy("");
    }
  }

  useEffect(() => { void load(); }, []);

  async function requestInvestigation() {
    setBusy("request");
    setError("");
    try {
      if (!purpose.trim() || !authorizationRef.trim() || !provider.trim()) {
        throw new Error("Purpose, authorization reference and provider are required.");
      }
      await apiFetch("/api/v1/investigations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          purpose: purpose.trim(),
          authorization_ref: authorizationRef.trim(),
          provider: provider.trim(),
          case_id: caseId.trim() || null,
        }),
      });
      setPurpose("");
      setAuthorizationRef("");
      setProvider("");
      setCaseId("");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Investigation request failed");
    } finally {
      setBusy("");
    }
  }

  async function transition(id: string, action: "start" | "stop") {
    setBusy(`${action}:${id}`);
    setError("");
    try {
      await apiFetch(`/api/v1/investigations/${encodeURIComponent(id)}/${action}`, { method: "POST" });
      await load();
      await loadDetail(id);
    } catch (e) {
      setError(e instanceof Error ? e.message : `Investigation ${action} failed`);
    } finally {
      setBusy("");
    }
  }

  return (
    <main className="min-h-screen bg-[#05070a] p-6 text-[#e8eef6]">
      <div className="mx-auto max-w-7xl space-y-5">
        <header>
          <div className="text-[10px] uppercase tracking-[.16em] text-[#5a6675]">Security Operations</div>
          <h1 className="mt-1 text-2xl font-semibold">Investigation</h1>
          <p className="mt-1 text-xs text-[#8a97a8]">Authorized investigation sessions, lifecycle control and evidence trace.</p>
        </header>

        {error && <ServiceError message={error} />}

        <ServiceSection title="Request investigation">
          <div className="grid gap-3 md:grid-cols-2">
            <label className="text-xs text-[#8a97a8]">Purpose
              <input value={purpose} onChange={e => setPurpose(e.target.value)} maxLength={500} className="mt-1 h-9 w-full border border-[#2a3646] bg-[#030508] px-2 text-sm" placeholder="Why this investigation is authorized" />
            </label>
            <label className="text-xs text-[#8a97a8]">Authorization reference
              <input value={authorizationRef} onChange={e => setAuthorizationRef(e.target.value)} maxLength={500} className="mt-1 h-9 w-full border border-[#2a3646] bg-[#030508] px-2 text-sm" placeholder="Approval / authorization reference" />
            </label>
            <label className="text-xs text-[#8a97a8]">Provider
              <input value={provider} onChange={e => setProvider(e.target.value)} maxLength={120} className="mt-1 h-9 w-full border border-[#2a3646] bg-[#030508] px-2 text-sm" placeholder="Configured forensics provider" />
            </label>
            <label className="text-xs text-[#8a97a8]">Case ID <span className="text-[#5a6675]">(optional)</span>
              <input value={caseId} onChange={e => setCaseId(e.target.value)} className="mt-1 h-9 w-full border border-[#2a3646] bg-[#030508] px-2 font-mono text-sm" placeholder="Case UUID" />
            </label>
          </div>
          <button disabled={!!busy} onClick={() => void requestInvestigation()} className="mt-4 h-9 border border-[#00d9ff] px-4 text-xs text-[#00d9ff] disabled:opacity-40">
            {busy === "request" ? "Requesting…" : "Create authorized request"}
          </button>
        </ServiceSection>

        {loading ? <ServiceLoading /> : (
          <ServiceSection title="Investigation sessions" count={items.length}>
            <ServiceTable rows={items} columns={[
              { key: "status", label: "Status" },
              { key: "provider", label: "Provider" },
              { key: "purpose", label: "Purpose" },
              { key: "authorization_ref", label: "Authorization" },
              { key: "case_id", label: "Case" },
              { key: "created_at", label: "Created" },
            ]} empty={<ServiceEmpty title="No investigation sessions" detail="No live investigation has been requested for this tenant." />} />
            {items.length > 0 && (
              <div className="mt-4 flex flex-wrap gap-2">
                {items.map(item => (
                  <div key={item.id} className="flex items-center gap-3 border border-[#1a2330] px-3 py-2 text-[10px]">
                    <button onClick={() => void loadDetail(item.id)} className="font-mono text-[#8a97a8]">
                      {busy === `detail:${item.id}` ? "Loading…" : item.id}
                    </button>
                    {item.status === "requested" && (
                      <button disabled={!!busy} onClick={() => void transition(item.id, "start")} className="text-[#00d9ff] disabled:opacity-40">
                        {busy === `start:${item.id}` ? "Starting…" : "Approve / start"}
                      </button>
                    )}
                    {item.status === "running" && (
                      <button disabled={!!busy} onClick={() => void transition(item.id, "stop")} className="text-[#ffb84d] disabled:opacity-40">
                        {busy === `stop:${item.id}` ? "Stopping…" : "Stop"}
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </ServiceSection>
        )}

        {selected && (
          <>
            <ServiceSection title="Selected session">
              <div className="grid gap-3 sm:grid-cols-4">
                <Metric label="Status" value={selected.session.status ?? "—"} />
                <Metric label="Provider" value={selected.session.provider ?? "—"} />
                <Metric label="Started" value={fmt(selected.session.started_at)} />
                <Metric label="Completed" value={fmt(selected.session.completed_at)} />
              </div>
              <div className="mt-4 grid gap-3 md:grid-cols-2 text-xs">
                <Detail label="Purpose" value={selected.session.purpose} />
                <Detail label="Authorization" value={selected.session.authorization_ref} />
                <Detail label="Case" value={selected.session.case_id} />
                <Detail label="Provider session" value={selected.session.provider_session_id} />
              </div>
            </ServiceSection>

            <ServiceSection title="Evidence" count={selected.evidence.length}>
              <ServiceTable rows={selected.evidence} columns={[
                { key: "evidence_type", label: "Type" },
                { key: "operation_id", label: "Operation" },
                { key: "sha256", label: "SHA-256" },
                { key: "collector", label: "Collector" },
                { key: "observed_at", label: "Observed" },
                { key: "collected_at", label: "Collected" },
                { key: "object_ref", label: "Object" },
              ]} empty={<ServiceEmpty title="No evidence recorded" detail="This session has no persisted evidence yet." />} />
            </ServiceSection>

            <ServiceSection title="Event trace" count={selected.events.length}>
              <ServiceTable rows={selected.events} columns={[
                { key: "event_at", label: "Time" },
                { key: "event_type", label: "Event" },
                { key: "actor", label: "Actor" },
                { key: "payload", label: "Payload" },
              ]} empty={<ServiceEmpty title="No investigation events" detail="No lifecycle events are persisted for this session." />} />
            </ServiceSection>
          </>
        )}
      </div>
    </main>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return <div className="border border-[#1a2330] bg-[#080c11] p-4"><div className="text-[9px] uppercase tracking-[.12em] text-[#5a6675]">{label}</div><div className="mt-1 truncate font-mono text-sm text-[#e8eef6]" title={value}>{value}</div></div>;
}

function Detail({ label, value }: { label: string; value?: string | null }) {
  return <div><div className="text-[9px] uppercase tracking-[.12em] text-[#5a6675]">{label}</div><div className="mt-1 break-all font-mono text-[#8a97a8]">{value || "—"}</div></div>;
}
