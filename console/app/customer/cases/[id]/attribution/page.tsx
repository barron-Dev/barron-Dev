"use client";

import {useEffect,useState} from "react";
import {useParams} from "next/navigation";
import {apiFetch,setApiToken} from "@/lib/api";

type Attribution={id:string;actor_id:string|null;confidence:number;method:string;evidence:any;alternative_actors:any[];computed_at:string};
type Ttp={id:number;technique_id:string;confidence:number;detector:string;observed_at:string};

export default function AttributionPage(){
  const params=useParams<{id:string}>();
  const [data,setData]=useState<any>(null);
  const [error,setError]=useState("");
  const [loading,setLoading]=useState(true);

  async function load(){
    setLoading(true);setError("");
    try{
      setApiToken(sessionStorage.getItem("cyclothone_access_token")||"");
      setData(await apiFetch(`/api/v1/mobile-intelligence/cases/${encodeURIComponent(params.id)}/attribution`));
    }catch(e){setError(e instanceof Error?e.message:"Unable to load attribution");}
    finally{setLoading(false);}
  }

  useEffect(()=>{void load();},[params.id]);

  if(loading)return <main className="min-h-screen bg-[#05070a] text-[#e8eef6] p-6 text-xs">Loading live attribution…</main>;
  if(error)return <main className="min-h-screen bg-[#05070a] text-[#e8eef6] p-6"><div className="border border-[#ff2d55]/40 p-4 text-xs text-[#ff6b83]">{error}</div></main>;

  const actors=new Map((data?.actors??[]).map((a:any)=>[a.id,a]));
  const attrs:Attribution[]=data?.attributions??[];
  const ttps:Ttp[]=data?.ttps??[];

  return <main className="min-h-screen bg-[#05070a] text-[#e8eef6] p-6">
    <div className="mx-auto max-w-6xl">
      <div className="flex items-center justify-between border-b border-[#1a2330] pb-4">
        <div>
          <div className="text-[10px] uppercase tracking-[0.2em] text-[#5a6675]">MDI · Attribution</div>
          <h1 className="mt-2 text-2xl font-semibold">{data?.case?.title??data?.case?.case_number??params.id}</h1>
        </div>
        <button onClick={()=>void load()} className="border border-[#2a3646] px-3 py-2 text-[10px]">Refresh</button>
      </div>

      <section className="mt-6 border border-[#1a2330] bg-[#0a0e14] p-5">
        <h2 className="font-semibold">Observed TTPs ({ttps.length})</h2>
        {!ttps.length?<p className="mt-4 text-xs text-[#5a6675]">No live TTP observations are recorded for this case.</p>:
        <div className="mt-4 flex flex-wrap gap-2">{ttps.map(t=><span key={t.id} className="border border-[#2a3646] rounded px-2 py-1 text-[10px]">{t.technique_id} · {t.detector} · {(Number(t.confidence)*100).toFixed(0)}%</span>)}</div>}
      </section>

      <section className="mt-6 border border-[#1a2330] bg-[#0a0e14] p-5">
        <h2 className="font-semibold">Attribution evidence</h2>
        {!attrs.length?<p className="mt-4 text-xs text-[#5a6675]">No attribution result has been computed from live source-backed evidence yet.</p>:
        <div className="mt-4 space-y-3">{attrs.map(a=>{
          const actor=actors.get(a.actor_id);
          return <article key={a.id} className="border border-[#1a2330] p-4">
            <div className="flex items-center justify-between">
              <b>{actor?.name??"Unresolved actor"}</b>
              <span className="text-xs">confidence {(Number(a.confidence)*100).toFixed(1)}%</span>
            </div>
            <div className="mt-2 text-[10px] text-[#8a97a8]">method: {a.method} · computed {new Date(a.computed_at).toISOString()}</div>
            <div className="mt-2 flex flex-wrap gap-1">{(a.evidence?.sharedTtps??[]).map((t:string)=><span key={t} className="border border-[#2a3646] rounded px-1.5 py-0.5 text-[10px]">{t}</span>)}</div>
          </article>;
        })}</div>}
      </section>
    </div>
  </main>;
}
