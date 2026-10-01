"use client";

import { FormEvent, useEffect, useState } from "react";
import { apiFetch } from "../../../../lib/api";
import { ServiceEmpty, ServiceError, ServiceLoading } from "../../../../components/ServiceData";

type Row = Record<string, unknown>;
type Watch = Row & { id?: string; kind?: string; value?: string; label?: string; severity?: string };
type Alert = Row & { id?: string; title?: string; severity?: string; status?: string; case_id?: string | null };

const input = "w-full border border-[#1a2330] bg-[#090c11] px-3 py-2 text-xs text-[#e8eef6] outline-none focus:border-[#40556f]";
const button = "border border-[#2a394d] bg-[#0b1118] px-3 py-2 text-[10px] uppercase tracking-[.12em] text-[#d7e1ec] disabled:opacity-40";

const kinds = ["email","domain","ip","wallet","phone","company_name","executive_name","api_key_hash","employee_id","customer_id"];
const statuses = ["new","acknowledged","investigating","remediated","false_positive"];

export default function DarkWeb() {
  const [watchlist,setWatchlist]=useState<Watch[]>([]);
  const [alerts,setAlerts]=useState<Alert[]>([]);
  const [stats,setStats]=useState<Row|null>(null);
  const [findings,setFindings]=useState<Row[]>([]);
  const [loading,setLoading]=useState(true);
  const [busy,setBusy]=useState("");
  const [error,setError]=useState("");
  const [notice,setNotice]=useState("");
  const [kind,setKind]=useState("domain");
  const [value,setValue]=useState("");
  const [severity,setSeverity]=useState("high");
  const [status,setStatus]=useState("acknowledged");

  async function load(){
    setLoading(true); setError("");
    try{
      const [w,a,s,f]=await Promise.all([
        apiFetch<Watch[]>("/api/v1/darkweb/watchlist"),
        apiFetch<Alert[]>("/api/v1/darkweb/alerts"),
        apiFetch<Row>("/api/v1/darkweb/stats"),
        apiFetch<Row[]>("/api/v1/darkweb/findings")
      ]);
      setWatchlist(Array.isArray(w)?w:[]); setAlerts(Array.isArray(a)?a:[]);
      setStats(s??null); setFindings(Array.isArray(f)?f:[]);
    }catch(e){setError(e instanceof Error?e.message:"Could not load dark web intelligence");}
    finally{setLoading(false);}
  }
  useEffect(()=>{void load()},[]);

  async function add(e:FormEvent){
    e.preventDefault(); if(!value.trim()) return;
    setBusy("add"); setError(""); setNotice("");
    try{
      await apiFetch("/api/v1/darkweb/watchlist",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({kind,value:value.trim(),severity})});
      setValue(""); setNotice("Monitoring started."); await load();
    }catch(e){setError(e instanceof Error?e.message:"Could not start monitoring");}
    finally{setBusy("")}
  }
  async function remove(id:string){
    setBusy(id); setError(""); setNotice("");
    try{await apiFetch("/api/v1/darkweb/watchlist/"+encodeURIComponent(id),{method:"DELETE"});setNotice("Monitoring stopped.");await load();}
    catch(e){setError(e instanceof Error?e.message:"Could not stop monitoring");}
    finally{setBusy("")}
  }
  async function update(id:string){
    setBusy("status:"+id); setError(""); setNotice("");
    try{await apiFetch("/api/v1/darkweb/alerts/"+encodeURIComponent(id),{method:"PATCH",headers:{"Content-Type":"application/json"},body:JSON.stringify({status})});setNotice("Alert updated.");await load();}
    catch(e){setError(e instanceof Error?e.message:"Could not update alert");}
    finally{setBusy("")}
  }
  async function openCase(id:string){
    setBusy("case:"+id); setError(""); setNotice("");
    try{const r=await apiFetch<{case_id?:string}>("/api/v1/darkweb/alerts/"+encodeURIComponent(id)+"/open-case",{method:"POST"});setNotice(r.case_id?"Investigation case opened.":"Case opened.");await load();}
    catch(e){setError(e instanceof Error?e.message:"Could not open case");}
    finally{setBusy("")}
  }

  return <main className="min-h-screen bg-[#05070a] p-6 text-[#e8eef6]">
    <div className="mx-auto max-w-6xl space-y-5">
      <header>
        <h1 className="text-2xl font-semibold">Dark Web</h1>
        <p className="mt-1 text-xs text-[#8a97a8]">Monitor important information and act when Cyclothone finds exposure.</p>
      </header>
      {error&&<ServiceError message={error}/>}
      {notice&&<div className="border border-[#26384a] bg-[#091018] px-4 py-3 text-xs text-[#b9c9d9]">{notice}</div>}
      {loading?<ServiceLoading/>:<>
        <section className="grid gap-4 lg:grid-cols-[1.2fr_.8fr]">
          <div className="border border-[#1a2330] bg-[#0a0e14] p-5">
            <div className="text-sm font-medium">What do you want to monitor?</div>
            <p className="mt-1 text-xs text-[#687789]">Choose one target and start monitoring.</p>
            <form onSubmit={add} className="mt-4 space-y-2">
              <select className={input} value={kind} onChange={e=>setKind(e.target.value)}>{kinds.map(k=><option key={k} value={k}>{k.replaceAll("_"," ")}</option>)}</select>
              <input className={input} value={value} onChange={e=>setValue(e.target.value)} placeholder="example.com or person@company.com" required/>
              <select className={input} value={severity} onChange={e=>setSeverity(e.target.value)}><option value="medium">Medium importance</option><option value="high">High importance</option><option value="critical">Critical</option></select>
              <button className={button} disabled={busy==="add"}>{busy==="add"?"Starting…":"Start monitoring"}</button>
            </form>
          </div>
          <div className="border border-[#1a2330] bg-[#0a0e14] p-5">
            <div className="text-sm font-medium">Your results</div>
            <div className="mt-4 grid grid-cols-3 gap-2">
              <Metric label="Alerts" value={stats?.total_alerts??alerts.length}/>
              <Metric label="Critical" value={stats?.critical??0}/>
              <Metric label="Findings" value={findings.length}/>
            </div>
            <p className="mt-4 text-xs text-[#687789]">Results come from the configured intelligence sources. No result is shown unless Cyclothone has real data for your organization.</p>
          </div>
        </section>

        <section className="border border-[#1a2330] bg-[#0a0e14] p-5">
          <div className="flex items-center justify-between"><div><div className="text-sm font-medium">Monitoring</div><div className="text-xs text-[#687789]">Targets currently watched for your organization.</div></div><span className="text-xs text-[#687789]">{watchlist.length}</span></div>
          {watchlist.length===0?<ServiceEmpty title="Nothing is being monitored" detail="Add a target above to start."/>:<div className="mt-4 space-y-2">{watchlist.map(w=><div key={String(w.id)} className="flex flex-wrap items-center gap-3 border border-[#141d28] p-3"><div className="mr-auto"><div className="text-xs">{String(w.value??"")}</div><div className="text-[10px] text-[#687789]">{String(w.kind??"")} · {String(w.severity??"")}</div></div><button className={button} disabled={!!busy} onClick={()=>void remove(String(w.id))}>{busy===String(w.id)?"Stopping…":"Stop monitoring"}</button></div>)}</div>}
        </section>

        <section className="border border-[#1a2330] bg-[#0a0e14] p-5">
          <div className="text-sm font-medium">Alerts & findings</div>
          <div className="mt-4 space-y-2">
            {alerts.length===0&&findings.length===0?<ServiceEmpty title="No exposure found" detail="There are no current alerts or findings for your organization."/>:alerts.map(a=><div key={String(a.id)} className="flex flex-wrap items-center gap-3 border border-[#141d28] p-3"><div className="mr-auto"><div className="text-xs">{String(a.title??"Dark-web alert")}</div><div className="text-[10px] text-[#687789]">{String(a.severity??"")} · {String(a.status??"")}</div></div><select className="border border-[#2a394d] bg-[#090c11] px-2 py-2 text-[10px]" value={status} onChange={e=>setStatus(e.target.value)}>{statuses.map(s=><option key={s}>{s}</option>)}</select><button className={button} disabled={!!busy} onClick={()=>void update(String(a.id))}>Update</button><button className={button} disabled={!!busy||!!a.case_id} onClick={()=>void openCase(String(a.id))}>{a.case_id?"Case opened":"Investigate"}</button></div>)}
          </div>
        </section>
      </>}
    </div>
  </main>
}
function Metric({label,value}:{label:string;value:unknown}){return <div className="border border-[#1a2330] p-3"><div className="text-[9px] uppercase tracking-[.12em] text-[#5a6675]">{label}</div><div className="mt-1 text-xl font-mono">{String(value??0)}</div></div>}
