"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "../../../../lib/api";
import { ServiceEmpty, ServiceError, ServiceLoading, ServiceSection, ServiceTable } from "../../../../components/ServiceData";

type Row = Record<string, unknown>;

export default function DarkWeb() {
  const [watchlist, setWatchlist] = useState<Row[]>([]);
  const [alerts, setAlerts] = useState<Row[]>([]);
  const [stats, setStats] = useState<Row | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    void (async () => {
      setLoading(true);
      setError("");
      try {
        const [w, a, s] = await Promise.all([
          apiFetch<Row[]>("/api/v1/darkweb/watchlist"),
          apiFetch<Row[]>("/api/v1/darkweb/alerts"),
          apiFetch<Row>("/api/v1/darkweb/stats"),
        ]);
        setWatchlist(Array.isArray(w) ? w : []);
        setAlerts(Array.isArray(a) ? a : []);
        setStats(s ?? null);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Could not load dark web intelligence");
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  return (
    <main className="min-h-screen bg-[#05070a] p-6 text-[#e8eef6]">
      <div className="mx-auto max-w-6xl space-y-5">
        <header>
          <div className="text-[10px] uppercase tracking-[.16em] text-[#5a6675]">Intelligence</div>
          <h1 className="mt-1 text-2xl font-semibold">Dark Web Intelligence</h1>
          <p className="mt-1 text-xs text-[#8a97a8]">Tenant watchlists, alerts and live statistics.</p>
        </header>

        {error && <ServiceError message={error} />}
        {loading ? <ServiceLoading /> : (
          <>
            {stats && <ServiceSection title="Alert summary">
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
                {["total_alerts", "new", "critical", "high", "remediated"].map(key => (
                  <div key={key} className="border border-[#1a2330] bg-[#05070a] p-4">
                    <div className="text-[9px] uppercase tracking-[.12em] text-[#5a6675]">{key.replace("_", " ")}</div>
                    <div className="mt-2 font-mono text-xl">{String(stats[key] ?? 0)}</div>
                  </div>
                ))}
              </div>
            </ServiceSection>}

            <ServiceSection title="Watchlist" count={watchlist.length}>
              <ServiceTable rows={watchlist} columns={[
                { key: "kind", label: "Kind" },
                { key: "value", label: "Value" },
                { key: "label", label: "Label" },
                { key: "severity", label: "Severity" },
                { key: "created_at", label: "Created" },
              ]} empty={<ServiceEmpty title="No watchlist entries" detail="No tenant watch targets are configured." />} />
            </ServiceSection>

            <ServiceSection title="Alerts" count={alerts.length}>
              <ServiceTable rows={alerts} columns={[
                { key: "title", label: "Alert" },
                { key: "severity", label: "Severity" },
                { key: "status", label: "Status" },
                { key: "finding_id", label: "Finding" },
                { key: "created_at", label: "Created" },
              ]} />
            </ServiceSection>
          </>
        )}
      </div>
    </main>
  );
}
