"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "../../../../lib/api";
import { ServiceEmpty, ServiceError, ServiceLoading, ServiceSection, ServiceTable } from "../../../../components/ServiceData";

type Row = Record<string, unknown>;

export default function Developer() {
  const [apps, setApps] = useState<Row[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    void (async () => {
      setLoading(true);
      setError("");
      try {
        const data = await apiFetch<unknown>("/api/v1/developer/apps");
        setApps(Array.isArray(data) ? data : []);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Could not load developer applications");
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
          <h1 className="mt-1 text-2xl font-semibold">Developer Control Plane</h1>
          <p className="mt-1 text-xs text-[#8a97a8]">Authenticated developer applications. Secrets are never rendered from list endpoints.</p>
        </header>
        {error && <ServiceError message={error} />}
        {loading ? <ServiceLoading /> : (
          <ServiceSection title="Applications" count={apps.length}>
            <ServiceTable rows={apps} columns={[
              { key: "name", label: "Application" },
              { key: "status", label: "Status" },
              { key: "client_id", label: "Client ID" },
              { key: "created_at", label: "Created" },
              { key: "updated_at", label: "Updated" },
            ]} empty={<ServiceEmpty title="No developer applications" detail="No tenant developer application has been registered." />} />
          </ServiceSection>
        )}
      </div>
    </main>
  );
}
