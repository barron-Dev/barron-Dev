"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "../../../../lib/api";
import { ServiceEmpty, ServiceError, ServiceLoading, ServiceSection, ServiceTable } from "../../../../components/ServiceData";

type Row = Record<string, unknown>;

export default function PhysicalPage() {
  const [sites, setSites] = useState<Row[]>([]);
  const [correlations, setCorrelations] = useState<Row[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    void (async () => {
      setLoading(true);
      setError("");
      try {
        const [s, c] = await Promise.all([
          apiFetch<Row[]>("/api/v1/physical/sites"),
          apiFetch<Row[]>("/api/v1/physical/correlations"),
        ]);
        setSites(Array.isArray(s) ? s : []);
        setCorrelations(Array.isArray(c) ? c : []);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Could not load physical security");
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  return (
    <main className="min-h-screen bg-[#05070a] p-6 text-[#e8eef6]">
      <div className="mx-auto max-w-6xl space-y-5">
        <header>
          <div className="text-[10px] uppercase tracking-[.16em] text-[#5a6675]">Convergence</div>
          <h1 className="mt-1 text-2xl font-semibold">Physical Security</h1>
          <p className="mt-1 text-xs text-[#8a97a8]">Tenant sites and physical/digital security correlations.</p>
        </header>
        {error && <ServiceError message={error} />}
        {loading ? <ServiceLoading /> : (
          <>
            <ServiceSection title="Sites" count={sites.length}>
              <ServiceTable rows={sites} columns={[
                { key: "name", label: "Site" },
                { key: "country", label: "Country" },
                { key: "timezone", label: "Timezone" },
                { key: "status", label: "Status" },
                { key: "created_at", label: "Created" },
              ]} empty={<ServiceEmpty title="No physical sites" detail="No tenant physical-security site has been configured." />} />
            </ServiceSection>
            <ServiceSection title="Correlations" count={correlations.length}>
              <ServiceTable rows={correlations} columns={[
                { key: "correlation_type", label: "Type" },
                { key: "severity", label: "Severity" },
                { key: "status", label: "Status" },
                { key: "created_at", label: "Created" },
              ]} />
            </ServiceSection>
          </>
        )}
      </div>
    </main>
  );
}
