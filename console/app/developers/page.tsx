"use client";

import { FormEvent, useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";
import { AuthActions } from "@/components/AuthActions";

type App = {
  id: string;
  name: string;
  description?: string | null;
  active: boolean;
  created_at: string;
};

type Key = {
  id: string;
  app_id: string;
  key_prefix: string;
  scopes: string[];
  active: boolean;
  expires_at: string | null;
  created_at: string;
};

export default function Developers() {
  const [apps, setApps] = useState<App[]>([]);
  const [keys, setKeys] = useState<Key[]>([]);
  const [selectedApp, setSelectedApp] = useState("");
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState("");
  const [newKey, setNewKey] = useState("");
  const [loading, setLoading] = useState(true);
  const [working, setWorking] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  async function load() {
    setLoading(true);
    setError("");
    try {
      const data = await apiFetch<App[]>("/api/v1/developer/apps");
      setApps(data);
      const current = selectedApp && data.some((app) => app.id === selectedApp) ? selectedApp : data[0]?.id ?? "";
      setSelectedApp(current);
      if (current) {
        setKeys(await apiFetch<Key[]>(`/api/v1/developer/apps/${current}/keys`));
      } else {
        setKeys([]);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load developer access");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void load(); }, []);

  async function createApp(event: FormEvent) {
    event.preventDefault();
    if (!name.trim()) return;
    setWorking(true); setError(""); setMessage("");
    try {
      const app = await apiFetch<App>("/api/v1/developer/apps", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: name.trim(),
          allowed_scopes: scopes.split(",").map((s) => s.trim()).filter(Boolean),
        }),
      });
      setName("");
      setScopes("");
      setSelectedApp(app.id);
      setMessage("Application created.");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not create application");
    } finally { setWorking(false); }
  }

  async function createKey() {
    if (!selectedApp) return;
    setWorking(true); setError(""); setMessage(""); setNewKey("");
    try {
      const result = await apiFetch<{api_key?: string; key?: string; key_prefix?: string}>(`/api/v1/developer/apps/${selectedApp}/keys`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scopes: scopes.split(",").map((s) => s.trim()).filter(Boolean) }),
      });
      const secret = result.api_key ?? result.key;
      if (secret) setNewKey(secret);
      setMessage(secret ? "API key created. Copy it now; it may only be shown once." : "API key created.");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not create API key");
    } finally { setWorking(false); }
  }

  async function selectApp(id: string) {
    setSelectedApp(id);
    setNewKey("");
    setError("");
    try { setKeys(await apiFetch<Key[]>(`/api/v1/developer/apps/${id}/keys`)); }
    catch (e) { setError(e instanceof Error ? e.message : "Could not load API keys"); }
  }

  return (
    <main className="cyclo-water min-h-screen overflow-hidden text-[#e8eef6]">
      <header className="relative z-10 border-b border-white/10 bg-[#02090e]/70 px-6 py-4 backdrop-blur-2xl">
        <div className="mx-auto max-w-4xl">
          <span className="cyclo-mark font-semibold tracking-tight">◌ CYCLOTHONE</span>
          <span className="ml-3 text-[10px] uppercase tracking-[.16em] text-[#c2f35a]">Developer</span>
          <div className="ml-auto"><AuthActions /></div>
        </div>
      </header>

      <div className="relative z-10 mx-auto max-w-5xl px-5 py-10 md:px-8 md:py-14">
        <h1 className="text-2xl font-semibold">Developer access</h1>
        <p className="mt-2 max-w-xl text-sm leading-6 text-[#8a97a8]">
          Create an application, issue an API key, and use the Cyclothone API. Advanced runtime details stay out of this screen.
        </p>

        {error && <div className="mt-6 border border-[#6b3030] bg-[#160b0b] p-4 text-sm">{error}</div>}
        {message && <div className="mt-6 border border-[#244936] bg-[#0b160f] p-4 text-sm">{message}</div>}
        {newKey && (
          <div className="mt-4 border border-[#00ff9d] bg-[#07110c] p-4">
            <div className="text-[10px] uppercase tracking-[.16em] text-[#00ff9d]">New API key</div>
            <code className="mt-2 block break-all text-xs">{newKey}</code>
            <p className="mt-2 text-xs text-[#8a97a8]">Copy this key now. Cyclothone does not display secret material from list endpoints.</p>
          </div>
        )}

        <section className="cyclo-stage mt-8 p-6">
          <h2 className="font-medium">1. Create an application</h2>
          <form onSubmit={createApp} className="mt-4 grid gap-3 md:grid-cols-[1fr_1fr_auto]">
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Application name" className="rounded-2xl border border-white/10 bg-[#031019]/80 p-3 text-sm outline-none focus:border-[#c2f35a]/40" />
            <input value={scopes} onChange={(e) => setScopes(e.target.value)} placeholder="Scopes, comma separated (optional)" className="border border-[#2a3646] bg-[#05070a] p-3 text-sm" />
            <button disabled={working} className="rounded-full border border-[#c2f35a]/50 bg-[#c2f35a]/10 px-5 py-3 text-sm text-[#ddff9a] disabled:opacity-50">Create</button>
          </form>
        </section>

        <section className="cyclo-stage mt-4 p-6">
          <h2 className="font-medium">2. API access</h2>
          {loading ? <p className="mt-4 text-sm text-[#8a97a8]">Loading…</p> : apps.length === 0 ? (
            <p className="mt-4 text-sm text-[#8a97a8]">No applications are registered for this developer account.</p>
          ) : (
            <>
              <select value={selectedApp} onChange={(e) => void selectApp(e.target.value)} className="mt-4 w-full rounded-2xl border border-white/10 bg-[#031019]/80 p-3 text-sm outline-none focus:border-[#c2f35a]/40">
                {apps.map((app) => <option key={app.id} value={app.id}>{app.name}{app.active ? "" : " — inactive"}</option>)}
              </select>
              <button onClick={() => void createKey()} disabled={working || !selectedApp} className="mt-3 rounded-full border border-[#c2f35a]/50 bg-[#c2f35a]/10 px-5 py-3 text-sm text-[#ddff9a] disabled:opacity-50">Create API key</button>

              <div className="mt-6 border-t border-white/10 pt-5">
                <div className="text-[10px] uppercase tracking-[.16em] text-[#5a6675]">Existing keys</div>
                {keys.length === 0 ? <p className="mt-3 text-sm text-[#8a97a8]">No API keys.</p> : (
                  <div className="mt-3 space-y-2">
                    {keys.map((key) => (
                      <div key={key.id} className="flex items-center justify-between rounded-2xl border border-white/10 bg-white/[.02] p-3 text-xs">
                        <span>{key.key_prefix} · {key.active ? "Active" : "Revoked"}</span>
                        <span className="text-[#8a97a8]">{key.scopes.length ? key.scopes.join(", ") : "No scopes"}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
        </section>

        <section className="cyclo-stage mt-4 p-6">
          <h2 className="font-medium">3. Mobile & Digital Intelligence</h2>
          <p className="mt-2 text-sm leading-6 text-[#8a97a8]">Request the <code>mobile:intelligence</code> scope for an approved application. The API exposes authorized number, SIM/device, location, reachability and roaming intelligence. Every query requires an approved authority record; unavailable provider data is returned as an error, never fabricated.</p>
          <code className="mt-3 block text-xs text-[#c4cedb]">POST /api/v1/mobile-intelligence/query</code>
        </section>

        <section className="cyclo-stage mt-4 p-6">
          <h2 className="font-medium">4. Integrate</h2>
          <p className="mt-2 text-sm leading-6 text-[#8a97a8]">
            Use your API key with the Cyclothone API. Documentation and language examples can be added after the underlying API workflow is commissioned; this page does not invent a test request.
          </p>
        </section>
      </div>
    </main>
  );
}
