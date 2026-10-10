"use client";

import { FormEvent, useEffect, useState } from "react";
import { apiFetch } from "../../../../lib/api";
import { ServiceEmpty, ServiceError, ServiceLoading } from "../../../../components/ServiceData";

type Row = Record<string, unknown>;
type Watch = Row & { id?: string; kind?: string; value?: string; label?: string; severity?: string };
type Alert = Row & { id?: string; title?: string; severity?: string; status?: string; case_id?: string | null };
type SourceHealth = Row & { id?: string; name?: string; enabled?: boolean; health?: string; last_pull_at?: string | null; configuration_ready?: boolean };
type SourceRun = Row & { id?: string; source_id?: string; status?: string; stage?: string; progress_percent?: number; discovered_count?: number; processed_count?: number; matched_count?: number; alert_count?: number; error_count?: number; detail?: string; started_at?: string | null; updated_at?: string | null; completed_at?: string | null };

const input = "w-full border border-[#d8cbb4] bg-[#fffdf7] px-3 py-2 text-xs text-[#283746] outline-none focus:border-[#345d78] rounded-[1rem_.3rem_1rem_.3rem]";
const button = "border border-[#cbbda4] bg-[#f3ead9] px-3 py-2 text-[10px] uppercase tracking-[.12em] text-[#283746] hover:bg-[#e9dcc4] disabled:opacity-40 rounded-[.8rem_.25rem_.8rem_.25rem]";

const kinds = ["email","domain","ip","wallet","phone","company_name","executive_name","api_key_hash","employee_id","customer_id"];
const statuses = ["new","acknowledged","investigating","remediated","false_positive"];

export default function DarkWeb() {
  const [watchlist,setWatchlist]=useState<Watch[]>([]);
  const [alerts,setAlerts]=useState<Alert[]>([]);
  const [stats,setStats]=useState<Row|null>(null);
  const [findings,setFindings]=useState<Row[]>([]);
  const [sources,setSources]=useState<SourceHealth[]>([]);
  const [runs,setRuns]=useState<SourceRun[]>([]);
  const [runsAvailable,setRunsAvailable]=useState(true);
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
      const [w,a,s,f,src,runRows]=await Promise.all([
        apiFetch<Watch[]>("/api/v1/darkweb/watchlist"),
        apiFetch<Alert[]>("/api/v1/darkweb/alerts"),
        apiFetch<Row>("/api/v1/darkweb/stats"),
        apiFetch<Row[]>("/api/v1/darkweb/findings"),
        apiFetch<SourceHealth[]>("/api/v1/darkweb/sources").catch(()=>[]),
        apiFetch<SourceRun[]>("/api/v1/darkweb/runs").catch(()=>{setRunsAvailable(false);return []})
      ]);
      setWatchlist(Array.isArray(w)?w:[]); setAlerts(Array.isArray(a)?a:[]);
      setStats(s??null); setFindings(Array.isArray(f)?f:[]); setSources(Array.isArray(src)?src:[]); setRuns(Array.isArray(runRows)?runRows:[]);
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

  return <main className="min-h-screen bg-[#f7f1e5] p-4 text-[#283746] sm:p-6">
    <div className="mx-auto max-w-6xl space-y-5">
      <header>
        <div className="inline-flex items-center gap-2 border border-[#d8cbb4] bg-[#fffaf0] px-3 py-1 text-[10px] uppercase tracking-[.18em] text-[#536b79] rounded-[.8rem_.25rem_.8rem_.25rem]">Cyclothone · Intelligence</div><h1 className="mt-3 text-3xl font-semibold tracking-tight">Dark Web</h1>
        <p className="mt-1 text-xs text-[#756d61]">Monitor important information and act when Cyclothone finds exposure.</p>
      </header>
      {error&&<ServiceError message={error}/>}
      {notice&&<div className="border border-[#cbbda4] bg-[#fffaf0] px-4 py-3 text-xs text-[#283746] rounded-[1rem_.3rem_1rem_.3rem]">{notice}</div>}
      {loading?<ServiceLoading/>:<>
        <section className="grid gap-4 lg:grid-cols-[1.2fr_.8fr]">
          <div className="border border-[#d8cbb4] bg-[#fffaf0] p-5 shadow-[0_8px_30px_rgba(77,61,36,.05)] rounded-[1.4rem_.35rem_1.4rem_.35rem]">
            <div className="text-sm font-medium">What do you want to monitor?</div>
            <p className="mt-1 text-xs text-[#756d61]">Choose one target and start monitoring.</p>
            <form onSubmit={add} className="mt-4 space-y-2">
              <select className={input} value={kind} onChange={e=>setKind(e.target.value)}>{kinds.map(k=><option key={k} value={k}>{k.replaceAll("_"," ")}</option>)}</select>
              <input className={input} value={value} onChange={e=>setValue(e.target.value)} placeholder="example.com or person@company.com" required/>
              <select className={input} value={severity} onChange={e=>setSeverity(e.target.value)}><option value="medium">Medium importance</option><option value="high">High importance</option><option value="critical">Critical</option></select>
              <button className={button} disabled={busy==="add"}>{busy==="add"?"Starting…":"Start monitoring"}</button>
            </form>
          </div>
          <div className="border border-[#d8cbb4] bg-[#fffaf0] p-5 shadow-[0_8px_30px_rgba(77,61,36,.05)] rounded-[1.4rem_.35rem_1.4rem_.35rem]">
            <div className="text-sm font-medium">Your results</div>
            <div className="mt-4 grid grid-cols-3 gap-2">
              <Metric label="Alerts" value={stats?.total_alerts??alerts.length}/>
              <Metric label="Critical" value={stats?.critical??0}/>
              <Metric label="Findings" value={findings.length}/>
            </div>
            <p className="mt-4 text-xs text-[#756d61]">Results come from the configured intelligence sources. No result is shown unless Cyclothone has real data for your organization.</p>
          </div>
        </section>

        <section className="border border-[#d8cbb4] bg-[#fffaf0] p-5 shadow-[0_8px_30px_rgba(77,61,36,.05)] rounded-[1.4rem_.35rem_1.4rem_.35rem]">
          <div className="text-sm font-medium">Intelligence source health</div>
          <p className="mt-1 text-xs text-[#756d61]">Operational state from the service. “Healthy” means a recent pull succeeded; it does not guarantee a finding.</p>
          {sources.length===0?<ServiceEmpty title="Source health not available" detail="The source-health endpoint is not reachable for this session, or no sources are configured."/>:<div className="mt-3 grid gap-2 sm:grid-cols-2">{sources.map(source=><div key={String(source.id)} className="flex items-center gap-3 border border-[#e2d7c4] bg-[#fffdf8] p-3 rounded-[.9rem_.25rem_.9rem_.25rem]"><div className="mr-auto"><div className="text-xs">{String(source.name??source.id??"Source")}</div><div className="text-[10px] text-[#756d61]">{source.enabled?"Enabled":"Disabled"} · {source.last_pull_at?`Last pull ${String(source.last_pull_at)}`:"No recorded pull"}</div></div><span className="border border-[#26384a] px-2 py-1 text-[10px] uppercase">{String(source.health??"unknown").replaceAll("_"," ")}</span></div>)}</div>}
        </section>

        <section className="border border-[#d8cbb4] bg-[#fffaf0] p-5 shadow-[0_8px_30px_rgba(77,61,36,.05)] rounded-[1.4rem_.35rem_1.4rem_.35rem]">
          <div className="flex flex-wrap items-end justify-between gap-2"><div><div className="text-sm font-medium">Live processing</div><p className="mt-1 text-xs text-[#756d61]">Battery progress is calculated from recorded source-run events and actual returned records—not elapsed time.</p></div><span className="text-[10px] uppercase tracking-[.12em] text-[#756d61]">No simulated progress</span></div>
          {!runsAvailable?<ServiceEmpty title="Process telemetry not available" detail="The telemetry migration or API is unavailable. Percentages are withheld rather than estimated."/>:runs.length===0?<ServiceEmpty title="No recorded processing cycle" detail="No source run is recorded yet. Progress appears only after a real source cycle is persisted."/>:<div className="mt-4 space-y-3">{Array.from(new Map(runs.map(run=>[String(run.source_id),run])).values()).map(run=>{const pct=Math.max(0,Math.min(100,Number(run.progress_percent??0)));const source=sources.find(s=>String(s.id)===String(run.source_id));const steps=[["connecting_to_source","Connect to source"],["records_normalized","Fetch & normalize"],["matching_and_persisting","Match & persist"],["completed","Cycle completed"]];const rank=steps.findIndex(s=>s[0]===run.stage);return <div key={String(run.id)} className="border border-[#e2d7c4] bg-[#fffdf8] p-4 rounded-[1.1rem_.3rem_1.1rem_.3rem]"><div className="flex flex-wrap items-center gap-3"><div className="mr-auto"><div className="text-sm font-medium">{String(source?.name??run.source_id??"Intelligence source")}</div><div className="mt-1 text-[10px] text-[#756d61]">{String(run.detail??run.stage??"No process detail")}</div></div><div className="text-xl font-semibold tabular-nums">{pct}%</div></div><div className="mt-3 flex items-center gap-2"><div className="h-3 flex-1 border border-[#b8aa92] bg-[#f0e7d7] p-[2px] rounded-[.25rem]"><div role="progressbar" aria-label={String(source?.name??run.source_id)+" processing progress"} aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct} className="h-full bg-[#386a82]" style={{width:pct+"%"}}/></div><span className="text-[9px] uppercase tracking-[.1em] text-[#756d61]">{String(run.status??"running")}</span></div><div className="mt-4 grid gap-2 sm:grid-cols-4">{steps.map((step,i)=>{const done=run.stage==="completed"||rank>i;const current=rank===i;return <div key={step[0]} className={"border px-2 py-2 text-[10px] "+(done?"border-[#9db9a4] bg-[#edf3e9] text-[#315944]":current?"border-[#8eafc0] bg-[#eaf1f4] text-[#284f63]":"border-[#e2d7c4] text-[#8a8174]")+" rounded-[.7rem_.2rem_.7rem_.2rem]"}><div className="flex items-center gap-1"><span>{done?"✓":current?"●":"○"}</span><span>{step[1]}</span></div></div>})}</div><div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-5">{[["Returned",run.discovered_count],["Processed",run.processed_count],["Matched",run.matched_count],["Alerts",run.alert_count],["Errors",run.error_count]].map(([label,value])=><div key={String(label)} className="border border-[#e2d7c4] px-2 py-2 rounded-[.6rem_.2rem_.6rem_.2rem]"><div className="text-[9px] uppercase tracking-[.1em] text-[#756d61]">{String(label)}</div><div className="mt-1 text-base font-semibold tabular-nums">{String(value??0)}</div></div>)}</div><div className="mt-3 text-[10px] text-[#756d61]">Started {run.started_at?new Date(String(run.started_at)).toLocaleString():"time not recorded"}{run.completed_at?" · Finished "+new Date(String(run.completed_at)).toLocaleString():""}</div></div>})}</div>}
          <div className="mt-4 flex flex-wrap items-center gap-2 text-[10px] uppercase tracking-[.1em] text-[#756d61]"><span className="border border-[#d8cbb4] px-2 py-1 rounded-[.7rem_.2rem_.7rem_.2rem]">Source</span><span>→</span><span className="border border-[#d8cbb4] px-2 py-1 rounded-[.7rem_.2rem_.7rem_.2rem]">Normalize</span><span>→</span><span className="border border-[#d8cbb4] px-2 py-1 rounded-[.7rem_.2rem_.7rem_.2rem]">Match</span><span>→</span><span className="border border-[#d8cbb4] px-2 py-1 rounded-[.7rem_.2rem_.7rem_.2rem]">Persist evidence</span><span>→</span><span className="border border-[#d8cbb4] px-2 py-1 rounded-[.7rem_.2rem_.7rem_.2rem]">Results</span></div>
        </section>

        <section className="border border-[#d8cbb4] bg-[#fffaf0] p-5 shadow-[0_8px_30px_rgba(77,61,36,.05)] rounded-[1.4rem_.35rem_1.4rem_.35rem]">
          <div className="flex items-center justify-between"><div><div className="text-sm font-medium">Monitoring</div><div className="text-xs text-[#756d61]">Targets currently watched for your organization.</div></div><span className="text-xs text-[#756d61]">{watchlist.length}</span></div>
          {watchlist.length===0?<ServiceEmpty title="Nothing is being monitored" detail="Add a target above to start."/>:<div className="mt-4 space-y-2">{watchlist.map(w=><div key={String(w.id)} className="flex flex-wrap items-center gap-3 border border-[#e2d7c4] bg-[#fffdf8] p-3 rounded-[.9rem_.25rem_.9rem_.25rem]"><div className="mr-auto"><div className="text-xs">{String(w.value??"")}</div><div className="text-[10px] text-[#756d61]">{String(w.kind??"")} · {String(w.severity??"")}</div></div><button className={button} disabled={!!busy} onClick={()=>void remove(String(w.id))}>{busy===String(w.id)?"Stopping…":"Stop monitoring"}</button></div>)}</div>}
        </section>

        <section className="border border-[#d8cbb4] bg-[#fffaf0] p-5 shadow-[0_8px_30px_rgba(77,61,36,.05)] rounded-[1.4rem_.35rem_1.4rem_.35rem]">
          <div className="text-sm font-medium">Alerts & findings</div>
          <div className="mt-4 space-y-2">
            {alerts.length===0&&findings.length===0?<ServiceEmpty title="No exposure found" detail="There are no current alerts or findings for your organization."/>:alerts.map(a=><div key={String(a.id)} className="flex flex-wrap items-center gap-3 border border-[#e2d7c4] bg-[#fffdf8] p-3 rounded-[.9rem_.25rem_.9rem_.25rem]"><div className="mr-auto"><div className="text-xs">{String(a.title??"Dark-web alert")}</div><div className="text-[10px] text-[#756d61]">{String(a.severity??"")} · {String(a.status??"")}</div></div><select className="border border-[#d8cbb4] bg-[#fffdf7] px-2 py-2 text-[10px] text-[#283746] rounded-[.7rem_.2rem_.7rem_.2rem]" value={status} onChange={e=>setStatus(e.target.value)}>{statuses.map(s=><option key={s}>{s}</option>)}</select><button className={button} disabled={!!busy} onClick={()=>void update(String(a.id))}>Update</button><button className={button} disabled={!!busy||!!a.case_id} onClick={()=>void openCase(String(a.id))}>{a.case_id?"Case opened":"Investigate"}</button></div>)}
          </div>
        </section>
      </>}
    </div>
  </main>
}
function Metric({label,value}:{label:string;value:unknown}){return <div className="border border-[#d8cbb4] p-3 rounded-[.8rem_.25rem_.8rem_.25rem]"><div className="text-[9px] uppercase tracking-[.12em] text-[#756d61]">{label}</div><div className="mt-1 text-xl font-mono">{String(value??0)}</div></div>}
