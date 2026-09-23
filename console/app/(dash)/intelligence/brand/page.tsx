"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "../../../../lib/api";
import { ServiceEmpty, ServiceError, ServiceLoading, ServiceSection, ServiceTable } from "../../../../components/ServiceData";

type Row = Record<string, unknown>;

export default function BrandPage() {
  const [brands, setBrands] = useState<Row[]>([]);
  const [threats, setThreats] = useState<Row[]>([]);
  const [stats, setStats] = useState<Row | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    void (async () => {
      setLoading(true);
      setError("");
      try {
        const [b, t, s] = await Promise.all([
          apiFetch<Row[]>("/api/v1/brand/brands"),
          apiFetch<Row[]>("/api/v1/brand/threats?limit=200"),
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
    })();
  }, []);

  return (
    <main className="min-h-screen bg-[#05070a] p-6 text-[#e8eef6]">
      <div className="mx-auto max-w-6xl space-y-5">
        <header>
          <div className="text-[10px] uppercase tracking-[.16em] text-[#5a6675]">Intelligence</div>
          <h1 className="mt-1 text-2xl font-semibold">Brand Protection</h1>
          <p className="mt-1 text-xs text-[#8a97a8]">Live protected brands, impersonation threats and tenant statistics.</p>
        </header>

        {error && <ServiceError message={error} />}
        {loading ? <ServiceLoading /> : (
          <>
            {stats && <ServiceSection title="Threat summary">
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                {["total", "active"].map(key => (
                  <div key={key} className="border border-[#1a2330] bg-[#05070a] p-4">
                    <div className="text-[9px] uppercase tracking-[.12em] text-[#5a6675]">{key}</div>
                    <div className="mt-2 font-mono text-xl">{String(stats[key] ?? 0)}</div>
                  </div>
                ))}
              </div>
            </ServiceSection>}

            <ServiceSection title="Protected brands" count={brands.length}>
              <ServiceTable rows={brands} columns={[
                { key: "name", label: "Brand" },
                { key: "primary_domain", label: "Primary domain" },
                { key: "similarity_min", label: "Similarity threshold" },
                { key: "created_at", label: "Created" },
              ]} empty={<ServiceEmpty title="No protected brands" detail="No tenant brand has been configured yet." />} />
            </ServiceSection>

            <ServiceSection title="Threats" count={threats.length}>
              <ServiceTable rows={threats} columns={[
                { key: "kind", label: "Kind" },
                { key: "severity", label: "Severity" },
                { key: "status", label: "Status" },
                { key: "first_seen", label: "First seen" },
                { key: "last_seen", label: "Last seen" },
              ]} />
            </ServiceSection>
          </>
        )}
      </div>
    </main>
  );
}
