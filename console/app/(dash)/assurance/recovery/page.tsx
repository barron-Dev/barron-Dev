"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "../../../../lib/api";
import { ServiceError, ServiceLoading, ServiceSection } from "../../../../components/ServiceData";

type Data = Record<string, unknown>;

export default function RecoveryPage() {
  const [data, setData] = useState<Data | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    void (async () => {
      setLoading(true);
      setError("");
      try {
        setData(await apiFetch<Data>("/api/v1/assurance/recovery"));
      } catch (e) {
        setError(e instanceof Error ? e.message : "Could not load recovery status");
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  return (
    <main className="min-h-screen bg-[#05070a] p-6 text-[#e8eef6]">
      <div className="mx-auto max-w-5xl space-y-5">
        <header>
          <div className="text-[10px] uppercase tracking-[.16em] text-[#5a6675]">Assurance</div>
          <h1 className="mt-1 text-2xl font-semibold">Recovery</h1>
          <p className="mt-1 text-xs text-[#8a97a8]">Live recovery control-plane status. Restore remains fail-closed until the immutable vault is configured.</p>
        </header>
        {error && <ServiceError message={error} />}
        {loading ? <ServiceLoading /> : data && (
          <ServiceSection title="Recovery status">
            <pre className="max-h-[32rem] overflow-auto whitespace-pre-wrap break-words text-xs text-[#8a97a8]">{JSON.stringify(data, null, 2)}</pre>
          </ServiceSection>
        )}
      </div>
    </main>
  );
}
