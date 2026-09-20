"use client";
import {useEffect,useState} from "react";
import {apiFetch} from "../../../../lib/api";
type Row=Record<string,unknown>;
export default function Developer(){const[a,setA]=useState<Row[]>([]),[e,setE]=useState("");
useEffect(()=>{void apiFetch<unknown>("/api/v1/developer/apps").then(x=>setA(Array.isArray(x)?x:[])).catch(x=>setE(x instanceof Error?x.message:"Could not load developer apps"))},[]);
return <main className="min-h-screen bg-[#05070a] p-6 text-[#e8eef6]"><div className="mx-auto max-w-6xl space-y-5"><header><div className="text-[10px] uppercase tracking-[.16em] text-[#5a6675]">Platform</div><h1 className="mt-1 text-2xl font-semibold">Developer Control Plane</h1><p className="mt-1 text-xs text-[#8a97a8]">Authenticated developer applications. Secrets are never rendered from list endpoints.</p></header>{e&&<div className="border border-[#ff2d55]/40 p-3 text-xs text-[#ff6b83]">{e}</div>}<section className="border border-[#1a2330] bg-[#0a0e14] p-5"><h2 className="text-sm font-semibold">Applications ({a.length})</h2><pre className="mt-3 max-h-[36rem] overflow-auto whitespace-pre-wrap text-xs">{JSON.stringify(a,null,2)}</pre></section></div></main>}
