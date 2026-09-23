"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "../../../../lib/api";
import { ServiceEmpty, ServiceError, ServiceLoading, ServiceSection, ServiceTable } from "../../../../components/ServiceData";

type Row = Record<string, unknown>;

export default function FederationPage() {
  const [peers, setPeers] = useState<Row[]>([]);
  const [indicators, setIndicators] = useState<Row[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    void (async () => {
      setLoading(true);
      setError("");
      try {
        const [p, i] = await Promise.all([
          apiFetch<Row[]>("/api/v1/federation/peers"),
          apiFetch<Row[]>("/api/v1/federation/indicators"),
        ]);
        setPeers(Array.isArray(p) ? p : []);
        setIndicators(Array.isArray(i) ? i : []);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Could not load federation");
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  return (
    <main className="min-h-screen bg-[#05070a] p-6 text-[#e8eef6]">
      <div className="mx-auto max-w-6xl space-y-5">
        <header>
          <div className="text-[10px] uppercase tracking-[.16em] text-[#5a6675]">Platform</div>
          <h1 className="mt-1 text-2xl font-semibold">Threat Intelligence Federation</h1>
          <p className="mt-1 text-xs text-[#8a97a8]">Tenant-scoped federation peers and shared indicators.</p>
        </header>
        {error && <ServiceError message={error} />}
        {loading ? <ServiceLoading /> : (
          <>
            <ServiceSection title="Peers" count={peers.length}>
              <ServiceTable rows={peers} columns={[
                { key: "name", label: "Peer" },
                { key: "kind", label: "Kind" },
                { key: "country", label: "Country" },
                { key: "trust_level", label: "Trust" },
                { key: "status", label: "Status" },
                { key: "last_receive_at", label: "Last receive" },
              ]} empty={<ServiceEmpty title="No federation peers" detail="No tenant or platform federation peers are available." />} />
            </ServiceSection>
            <ServiceSection title="Indicators" count={indicators.length}>
              <ServiceTable rows={indicators} columns={[
                { key: "ioc_type", label: "IOC type" },
                { key: "category", label: "Category" },
                { key: "severity", label: "Severity" },
                { key: "confidence", label: "Confidence" },
                { key: "verified", label: "Verified" },
                { key: "last_seen", label: "Last seen" },
              ]} />
            </ServiceSection>
          </>
        )}
      </div>
    </main>
  );
}
