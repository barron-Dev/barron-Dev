'use client';

import { useEffect, useMemo, useState } from 'react';
import { buildAdjacency, pageRank } from '@/lib/mdi/algorithms/graph';

type Alert = {
  id: string;
  alert_type: string;
  subject_id?: string | null;
  severity: string;
  score?: number | null;
  action?: string | null;
  algorithm: string;
  explanation?: Record<string, unknown>;
  created_at: string;
};

type Risk = {
  score: number;
  band: string;
  signals: Array<{ k: string; lr: number; eff_lr: number; contrib: number }>;
  model_version: string;
};

type Edge = { src_id: string; dst_id: string; weight: number };

export function AdvancedLiveWidgets({ token, subjectId, edges = [] }: { token: string; subjectId?: string; edges?: Edge[] }) {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [risk, setRisk] = useState<Risk | null>(null);
  const [cells, setCells] = useState<Record<string, { count: number; lastSeen: string; confidence: number }>>({});
  const [streamState, setStreamState] = useState('connecting');

  useEffect(() => {
    if (!token) return;
    const controller = new AbortController();
    let stopped = false;
    const connect = async () => {
      try {
        const response = await fetch('/api/mdi/stream', {
          headers: { Authorization: `Bearer ${token}` },
          signal: controller.signal,
          cache: 'no-store',
        });
        if (!response.ok || !response.body) throw new Error(`stream_${response.status}`);
        setStreamState('live');
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';
        while (!stopped) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const frames = buffer.split('\n\n');
          buffer = frames.pop() ?? '';
          for (const frame of frames) {
            const dataLine = frame.split('\n').find(line => line.startsWith('data: '));
            if (!dataLine) continue;
            try {
              const value = JSON.parse(dataLine.slice(6));
              if (frame.startsWith('event: alert')) setAlerts(prev => [value, ...prev].slice(0, 50));
            } catch {}
          }
        }
      } catch {
        if (!stopped) setStreamState('reconnecting');
      } finally {
        if (!stopped) setTimeout(connect, 500);
      }
    };
    void connect();
    return () => { stopped = true; controller.abort(); };
  }, [token]);

  useEffect(() => {
    if (!token || !subjectId) return;
    const headers = { Authorization: `Bearer ${token}` };
    const load = async () => {
      const [r, g] = await Promise.all([
        fetch(`/api/mdi/advanced/risk/${encodeURIComponent(subjectId)}`, { headers, cache: 'no-store' }),
        fetch(`/api/mdi/advanced/geofence/${encodeURIComponent(subjectId)}`, { headers, cache: 'no-store' }),
      ]);
      if (r.ok) setRisk(await r.json());
      if (g.ok) setCells((await g.json()).cells ?? {});
    };
    void load();
    const timer = setInterval(load, 5000);
    return () => clearInterval(timer);
  }, [token, subjectId]);

  const ranked = useMemo(() => {
    const adj = buildAdjacency(edges.map(e => ({ src: e.src_id, dst: e.dst_id, weight: e.weight, confidence: 1, kind: 'related' })), false);
    return [...pageRank(adj, 25, 0.85).entries()].sort((a, b) => b[1] - a[1]).slice(0, 20);
  }, [edges]);

  const maxCell = Math.max(1, ...Object.values(cells).map(c => c.count));

  return (
    <section className="mt-6 grid gap-4 lg:grid-cols-2">
      <div className="border border-[#1a2330] bg-[#0a0e14] p-5 lg:col-span-2">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold">Live threat ticker</h2>
          <span className="text-[10px] uppercase tracking-wider text-[#5a6675]">{streamState}</span>
        </div>
        <div className="mt-3 max-h-64 overflow-auto space-y-2">
          {!alerts.length && <div className="text-xs text-[#5a6675]">No live advanced alerts.</div>}
          {alerts.map(alert => (
            <div key={alert.id} className="border border-[#1a2330] px-3 py-2 text-[11px]">
              <div className="flex justify-between"><span className="font-mono">{alert.alert_type}</span><span>{alert.severity}</span></div>
              <div className="mt-1 text-[#8a97a8]">{alert.algorithm} · {alert.action ?? 'review'}</div>
              <div className="mt-1 text-[10px] text-[#5a6675]">{new Date(alert.created_at).toLocaleString()}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="border border-[#1a2330] bg-[#0a0e14] p-5">
        <h2 className="text-sm font-semibold">Explainable risk</h2>
        {!risk ? <div className="mt-4 text-xs text-[#5a6675]">Select a subject to load risk evidence.</div> : (
          <>
            <div className="mt-4 text-3xl font-mono">{risk.score.toFixed(2)}</div>
            <div className="text-[10px] uppercase tracking-wider text-[#5a6675]">{risk.band} · {risk.model_version}</div>
            <div className="mt-4 space-y-2">
              {risk.signals?.map((signal, i) => (
                <div key={i} className="flex justify-between border-b border-[#111823] py-2 text-[11px]">
                  <span>{signal.k}</span><span>LR {signal.lr} · eff {signal.eff_lr} · {signal.contrib}</span>
                </div>
              ))}
            </div>
          </>
        )}
      </div>

      <div className="border border-[#1a2330] bg-[#0a0e14] p-5">
        <h2 className="text-sm font-semibold">Geofence / H3 history</h2>
        {!Object.keys(cells).length ? <div className="mt-4 text-xs text-[#5a6675]">No location cells returned for the last 30 days.</div> : (
          <div className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-3">
            {Object.entries(cells).slice(0, 30).map(([cell, value]) => (
              <div key={cell} className="border border-[#1a2330] p-2">
                <div className="truncate font-mono text-[9px]">{cell}</div>
                <div className="mt-2 h-2 bg-[#151c25]"><div className="h-2 bg-[#00d9ff]" style={{ width: `${Math.round(value.count / maxCell * 100)}%` }} /></div>
                <div className="mt-1 text-[9px] text-[#5a6675]">{value.count} observations · {Math.round(value.confidence * 100)}% conf</div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="border border-[#1a2330] bg-[#0a0e14] p-5 lg:col-span-2">
        <h2 className="text-sm font-semibold">Relationship graph ranking</h2>
        {!ranked.length ? <div className="mt-4 text-xs text-[#5a6675]">No graph edges supplied.</div> : (
          <div className="mt-4 grid gap-2 md:grid-cols-2">
            {ranked.map(([id, score]) => (
              <div key={id} className="flex justify-between border-b border-[#111823] py-2 text-[11px]">
                <span className="font-mono truncate">{id}</span><span>{score.toFixed(6)}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}
