"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "../../../../lib/api";

type Node = { id:string; node_type:string; external_id:string; label:string|null; criticality:number; last_seen:string };
type Simulation = { id:string; action:string; target_node_id:string; impact_score:number|null; cascade_size:number|null; recommendation:string|null; duration_ms:number|null; created_at:string };
type Stats = { nodes:number; edges:number; simulations:number; avg_impact:number };

export default function DigitalTwinPage(){
  const [stats,setStats]=useState<Stats|null>(null);
  const [nodes,setNodes]=useState<Node[]>([]);
  const [simulations,setSimulations]=useState<Simulation[]>([]);
  const [error,setError]=useState("");

  useEffect(()=>{
    void Promise.all([
      apiFetch<Stats>("/api/v1/twin/stats"),
      apiFetch<Node[]>("/api/v1/twin/nodes?limit=100"),
      apiFetch<Simulation[]>("/api/v1/twin/simulations?limit=50"),
    ]).then(([s,n,r])=>{setStats(s);setNodes(n);setSimulations(r);setError("")})
      .catch(e=>setError(e instanceof Error?e.message:"Could not load Digital Twin"));
  },[]);

  return <main className="min-h-screen bg-[#05070a] p-6 text-[#e8eef6]">
    <div className="mx-auto max-w-7xl space-y-5">
      <header>
        <div className="text-[10px] uppercase tracking-[.16em] text-[#5a6675]">Convergence</div>
        <h1 className="mt-1 text-2xl font-semibold">Digital Twin</h1>
        <p className="mt-1 text-xs text-[#8a97a8]">Tenant-scoped authoritative topology and advisory impact simulation. Simulation never grants execution authority.</p>
      </header>
      {error&&<div role="alert" className="border border-[#ff2d55]/40 p-3 text-xs text-[#ff6b83]">{error}</div>}
      <section className="grid gap-3 md:grid-cols-4">
        {[
          ["Nodes",stats?.nodes??"—"],["Edges",stats?.edges??"—"],["Simulations",stats?.simulations??"—"],
          ["Avg impact",stats ? Math.round(stats.avg_impact*100)+"%" : "—"]
        ].map(([label,value])=><div key={label} className="border border-[#1a2330] bg-[#0a0e14] p-4"><div className="font-mono text-2xl">{value}</div><div className="mt-1 text-[10px] uppercase tracking-[.14em] text-[#5a6675]">{label}</div></div>)}
      </section>
      <section className="border border-[#1a2330] bg-[#0a0e14] p-5">
        <h2 className="text-sm font-semibold">World-state nodes ({nodes.length})</h2>
        <div className="mt-3 overflow-auto"><table className="w-full text-left text-xs"><thead className="text-[#5a6675]"><tr><th className="py-2">Type</th><th>Identity</th><th>Criticality</th><th>Last seen</th></tr></thead><tbody>{nodes.map(n=><tr key={n.id} className="border-t border-[#1a2330]"><td className="py-2">{n.node_type}</td><td>{n.label??n.external_id}</td><td>{Math.round(n.criticality*100)}%</td><td>{new Date(n.last_seen).toLocaleString()}</td></tr>)}</tbody></table></div>
      </section>
      <section className="border border-[#1a2330] bg-[#0a0e14] p-5">
        <h2 className="text-sm font-semibold">Recent simulations ({simulations.length})</h2>
        <div className="mt-3 overflow-auto"><table className="w-full text-left text-xs"><thead className="text-[#5a6675]"><tr><th className="py-2">Action</th><th>Impact</th><th>Cascade</th><th>Duration</th><th>Created</th></tr></thead><tbody>{simulations.map(s=><tr key={s.id} className="border-t border-[#1a2330]"><td className="py-2">{s.action}</td><td>{s.impact_score==null?"—":Math.round(s.impact_score*100)+"%"}</td><td>{s.cascade_size??"—"}</td><td>{s.duration_ms==null?"—":s.duration_ms+"ms"}</td><td>{new Date(s.created_at).toLocaleString()}</td></tr>)}</tbody></table></div>
      </section>
    </div>
  </main>;
}
