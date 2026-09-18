"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

const API = process.env.NEXT_PUBLIC_SENTINEL_API_URL ?? "";

type Device = {
  id: string;
  hostname: string;
  name: string;
  os: string;
  os_version: string | null;
  arch: string | null;
  platform: string;
  platform_version: string | null;
  agent_version: string | null;
  last_seen_at: string | null;
  status: string;
  created_at: string;
  updated_at: string;
  cert_fingerprint: string | null;
  attestation?: Record<string, unknown>;
};

type DeviceResponse = {
  items: Device[];
  pagination: { limit: number; offset: number; total: number; has_more: boolean };
};

function headers(): HeadersInit {
  const token = typeof window === "undefined" ? "" : sessionStorage.getItem("sentinel_access_token") ?? "";
  return token ? { Authorization: `Bearer ${token}` } : {};
}

function relativeTime(value: string | null): string {
  if (!value) return "never";
  const delta = Date.now() - Date.parse(value);
  if (!Number.isFinite(delta)) return "unknown";
  const minutes = Math.floor(delta / 60000);
  if (minutes < 1) return "now";
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h`;
  return `${Math.floor(hours / 24)}d`;
}

export default function DevicesPage() {
  const [data, setData] = useState<DeviceResponse | null>(null);
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("");
  const [platform, setPlatform] = useState("");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<Device | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const limit = 50;

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const params = new URLSearchParams({ limit: String(limit), offset: String(offset), sort: "last_seen_at", direction: "desc" });
      if (search.trim()) params.set("search", search.trim());
      if (status) params.set("status", status);
      if (platform) params.set("platform", platform);
      const response = await fetch(`${API}/api/v1/console/devices?${params}`, { headers: headers(), cache: "no-store" });
      if (!response.ok) throw new Error(response.status === 401 || response.status === 403 ? "Authentication required" : `Request failed (${response.status})`);
      setData((await response.json()) as DeviceResponse);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load devices");
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [offset, platform, search, status]);

  useEffect(() => { void load(); }, [load]);

  const openDetail = useCallback(async (device: Device) => {
    setSelected(device);
    setDetailLoading(true);
    try {
      const response = await fetch(`${API}/api/v1/console/devices/${encodeURIComponent(device.id)}`, { headers: headers(), cache: "no-store" });
      if (!response.ok) throw new Error(response.status === 401 || response.status === 403 ? "Authentication required" : response.status === 404 ? "Device not found" : `Request failed (${response.status})`);
      setSelected((await response.json()) as Device);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load device detail");
    } finally {
      setDetailLoading(false);
    }
  }, []);

  const platforms = useMemo(() => Array.from(new Set((data?.items ?? []).map((item) => item.platform).filter(Boolean))).sort(), [data]);

  return (
    <main className="page-shell" aria-labelledby="devices-title">
      <header className="page-header">
        <div>
          <p className="eyebrow">ENDPOINT CONTROL PLANE</p>
          <h1 id="devices-title">Devices</h1>
          <p className="muted">Tenant-scoped endpoint inventory from the Cyclothone control plane.</p>
        </div>
        <div className="header-stat" aria-live="polite"><span>Total</span><strong>{data?.pagination.total ?? "—"}</strong></div>
      </header>

      <section className="toolbar" aria-label="Device filters">
        <input aria-label="Search hostname or device name" placeholder="Search hostname / name" value={search} onChange={(event) => { setSearch(event.target.value); setOffset(0); }} />
        <select aria-label="Filter by status" value={status} onChange={(event) => { setStatus(event.target.value); setOffset(0); }}>
          <option value="">All status</option><option value="online">Online</option><option value="offline">Offline</option><option value="quarantined">Quarantined</option>
        </select>
        <select aria-label="Filter by platform" value={platform} onChange={(event) => { setPlatform(event.target.value); setOffset(0); }}>
          <option value="">All platforms</option>{platforms.map((value) => <option key={value} value={value}>{value}</option>)}
        </select>
        <button type="button" onClick={() => void load()} disabled={loading}>{loading ? "Loading…" : "Refresh"}</button>
      </section>

      {error && <div className="error-banner" role="alert">{error}</div>}
      <section className="table-wrap" aria-label="Devices">
        <table>
          <thead><tr><th>Device</th><th>Platform</th><th>Agent</th><th>Status</th><th>Last seen</th><th>Certificate</th></tr></thead>
          <tbody>
            {data?.items.map((device) => (
              <tr key={device.id} tabIndex={0} onClick={() => void openDetail(device)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); void openDetail(device); } }}>
                <td><strong>{device.name || device.hostname}</strong><small>{device.hostname} · {device.id}</small></td>
                <td>{device.platform}{device.platform_version ? ` ${device.platform_version}` : ""}</td>
                <td className="mono">{device.agent_version ?? "—"}</td>
                <td><span className={`status status-${device.status}`}>{device.status}</span></td>
                <td className="mono">{relativeTime(device.last_seen_at)}</td>
                <td className="mono">{device.cert_fingerprint ? `${device.cert_fingerprint.slice(0, 12)}…` : "—"}</td>
              </tr>
            ))}
            {!loading && !data?.items.length && <tr><td colSpan={6} className="empty">No devices match the current filters.</td></tr>}
          </tbody>
        </table>
      </section>

      <footer className="pager">
        <span>{data ? `${data.pagination.total === 0 ? 0 : data.pagination.offset + 1}–${Math.min(data.pagination.offset + data.pagination.limit, data.pagination.total)} of ${data.pagination.total}` : "—"}</span>
        <div><button type="button" onClick={() => setOffset((value) => Math.max(0, value - limit))} disabled={!offset || loading}>Previous</button><button type="button" onClick={() => setOffset((value) => value + limit)} disabled={!data?.pagination.has_more || loading}>Next</button></div>
      </footer>

      {selected && (
        <aside className="detail-panel" aria-label="Selected device">
          <button className="close" type="button" onClick={() => setSelected(null)} aria-label="Close device details">×</button>
          <p className="eyebrow">DEVICE DETAIL</p><h2>{selected.name || selected.hostname}</h2>
          {detailLoading && <p className="muted" aria-live="polite">Loading authoritative device state…</p>}
          <dl>
            <dt>Device ID</dt><dd className="mono">{selected.id}</dd>
            <dt>Hostname</dt><dd>{selected.hostname}</dd>
            <dt>OS</dt><dd>{selected.os}{selected.os_version ? ` ${selected.os_version}` : ""}</dd>
            <dt>Architecture</dt><dd>{selected.arch ?? "—"}</dd>
            <dt>Agent</dt><dd>{selected.agent_version ?? "—"}</dd>
            <dt>Status</dt><dd>{selected.status}</dd>
            <dt>Last seen</dt><dd>{selected.last_seen_at ?? "never"}</dd>
            <dt>Certificate fingerprint</dt><dd className="mono break">{selected.cert_fingerprint ?? "—"}</dd>
            <dt>Attestation fields</dt><dd className="mono break">{selected.attestation && Object.keys(selected.attestation).length ? Object.keys(selected.attestation).join(", ") : "—"}</dd>
          </dl>
        </aside>
      )}
    </main>
  );
}
