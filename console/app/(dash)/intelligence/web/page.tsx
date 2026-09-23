"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "../../../../lib/api";
import { ServiceEmpty, ServiceError, ServiceLoading, ServiceSection, ServiceTable } from "../../../../components/ServiceData";

type Row = Record<string, unknown>;

export default function WebIntel() {
  const [targets, setTargets] = useState<Row[]>([]);
  const [pages, setPages] = useState<Row[]>([]);
  const [dorks, setDorks] = useState<Row[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    void (async () => {
      setLoading(true);
      setError("");
      try {
        const [t, p, d] = await Promise.all([
          apiFetch<Row[]>("/api/v1/web-intel/targets"),
          apiFetch<Row[]>("/api/v1/web-intel/pages"),
          apiFetch<Row[]>("/api/v1/web-intel/dorks"),
        ]);
        setTargets(Array.isArray(t) ? t : []);
        setPages(Array.isArray(p) ? p : []);
        setDorks(Array.isArray(d) ? d : []);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Could not load web intelligence");
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
          <h1 className="mt-1 text-2xl font-semibold">Web Intelligence</h1>
          <p className="mt-1 text-xs text-[#8a97a8]">Live crawl targets, discovered pages and tenant dorks.</p>
        </header>

        {error && <ServiceError message={error} />}
        {loading ? <ServiceLoading /> : (
          <>
            <ServiceSection title="Targets" count={targets.length}>
              <ServiceTable rows={targets} columns={[
                { key: "layer", label: "Layer" },
                { key: "kind", label: "Kind" },
                { key: "url", label: "Target" },
                { key: "enabled", label: "Enabled" },
                { key: "last_status", label: "Last status" },
                { key: "last_crawl_at", label: "Last crawl" },
              ]} empty={<ServiceEmpty title="No crawl targets" detail="Add a real tenant target before crawling." />} />
            </ServiceSection>

            <ServiceSection title="Pages" count={pages.length}>
              <ServiceTable rows={pages} columns={[
                { key: "url", label: "URL" },
                { key: "status_code", label: "HTTP" },
                { key: "content_type", label: "Content type" },
                { key: "severity", label: "Severity" },
                { key: "first_seen", label: "First seen" },
              ]} />
            </ServiceSection>

            <ServiceSection title="Dorks" count={dorks.length}>
              <ServiceTable rows={dorks} columns={[
                { key: "query", label: "Query" },
                { key: "engine", label: "Engine" },
                { key: "enabled", label: "Enabled" },
                { key: "created_at", label: "Created" },
              ]} />
            </ServiceSection>
          </>
        )}
      </div>
    </main>
  );
}
