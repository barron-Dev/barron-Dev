"use client";
import {useEffect,useState} from "react";
import {apiFetch,setApiToken} from "../../../../../lib/api";
type ChatMessage={role:"user"|"assistant";content:string;citations?:any[];created_at?:string};
type ChatThread={id:string;preview:string;created_at?:string};\ntype UsageInfo={provider?:string|null;model?:string|null;inputTokens?:number|null;outputTokens?:number|null;totalTokens?:number|null;contextWindowTokens?:number|null;contextUsagePercent?:number|null;estimatedCostUsd?:number|null;measurement?:string;costBasis?:string};
export default function CopilotPage(){
 const [input,setInput]=useState("");
 const [messages,setMessages]=useState<ChatMessage[]>([]);
 const [threads,setThreads]=useState<ChatThread[]>([]);
 const [busy,setBusy]=useState(false);
 const [error,setError]=useState("");
 const [historyBusy,setHistoryBusy]=useState(true);\n const [usage,setUsage]=useState<UsageInfo|null>(null);
 const [threadId,setThreadId]=useState(()=>crypto.randomUUID());
 function auth(){setApiToken(sessionStorage.getItem("cyclothone_access_token")||"");}
 async function refreshThreads(){
  auth();
  const r=await apiFetch<any>("/api/v1/mobile-intelligence/copilot/threads",{method:"GET"});
  setThreads(Array.isArray(r.threads)?r.threads:[]);
 }
 useEffect(()=>{let active=true;(async()=>{try{auth();const r=await apiFetch<any>("/api/v1/mobile-intelligence/copilot/threads",{method:"GET"});if(active)setThreads(Array.isArray(r.threads)?r.threads:[]);}catch(e){if(active)setError(e instanceof Error?e.message:"Could not load saved chats");}finally{if(active)setHistoryBusy(false);}})();return()=>{active=false;};},[]);
 async function openThread(id:string){
  if(busy)return;
  setError("");setHistoryBusy(true);
  try{auth();const r=await apiFetch<any>("/api/v1/mobile-intelligence/copilot/threads/"+encodeURIComponent(id),{method:"GET"});setThreadId(id);setMessages(Array.isArray(r.messages)?r.messages:[]);setUsage(null);}
  catch(e){setError(e instanceof Error?e.message:"Could not restore this chat");}
  finally{setHistoryBusy(false);}
 }
 function newChat(){if(busy)return;setThreadId(crypto.randomUUID());setMessages([]);setUsage(null);setError("");}
 async function send(){
  if(!input.trim()||busy)return;
  const q=input.trim();setInput("");setMessages(m=>[...m,{role:"user",content:q}]);setBusy(true);setError("");
  try{
   auth();
   const r=await apiFetch<any>("/api/v1/mobile-intelligence/copilot",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({thread_id:threadId,message:q})});
   setMessages(m=>[...m,{role:"assistant",content:r.answer,citations:r.citations||[]}]);setUsage(r.usage&&typeof r.usage==="object"?r.usage:null);
   try{await refreshThreads();}catch{/* The conversation response is saved; history refresh can retry on next load. */}
  }catch(e){setError(e instanceof Error?e.message:"Copilot request failed. Check connection before retrying.");}
  finally{setBusy(false);}
 }
 return <main className="min-h-screen bg-[#05070a] text-[#e8eef6] p-4 md:p-6"><div className="max-w-7xl mx-auto">
  <header className="mb-5 flex flex-wrap items-center justify-between gap-3"><div><div className="text-xs opacity-60">Cyclothone · Kontrol</div><h1 className="text-2xl font-semibold">Kontrol Control Room</h1><p className="text-sm opacity-70">Whole-platform assistance · conversations auto-save on the server</p></div><div className="flex gap-2 text-xs"><span className="border border-[#1a2330] rounded px-3 py-2">Context: {typeof usage?.contextUsagePercent==="number"?`${usage.contextUsagePercent}% of ${usage.contextWindowTokens} tokens`:"not reported"}</span><span className="border border-[#1a2330] rounded px-3 py-2">Tokens: {typeof usage?.totalTokens==="number"?usage.totalTokens.toLocaleString():"not reported"}</span><span className="border border-[#1a2330] rounded px-3 py-2">Cost: {typeof usage?.estimatedCostUsd==="number"?`~${usage.estimatedCostUsd.toFixed(6)} USD`:"not configured"}</span></div></header>
  <div className="grid grid-cols-1 md:grid-cols-[250px_minmax(0,1fr)] gap-4">
   <aside className="border border-[#1a2330] rounded-lg p-3 h-fit"><button className="w-full border border-sky-700 rounded px-3 py-2 text-left" onClick={newChat} disabled={busy}>＋ New chat</button><div className="mt-4 mb-2 text-xs uppercase tracking-wide opacity-60">Saved conversations</div>{historyBusy&&<div className="text-sm opacity-60 p-2">Loading history…</div>}{!historyBusy&&threads.length===0&&<div className="text-sm opacity-50 p-2">No saved conversations found.</div>}<div className="space-y-1 max-h-[60vh] overflow-y-auto">{threads.map(t=><button key={t.id} onClick={()=>openThread(t.id)} disabled={busy} className={"w-full text-left rounded p-2 text-sm border "+(t.id===threadId?"border-sky-700 bg-[#0b1724]":"border-transparent hover:border-[#263446]")}><div className="truncate">{t.preview||"Saved conversation"}</div><div className="text-[10px] opacity-50 mt-1">{t.created_at?new Date(t.created_at).toLocaleString():"Saved"}</div></button>)}</div><div className="mt-4 border-t border-[#1a2330] pt-3 text-xs opacity-60">History is stored server-side. Usage reflects provider-reported tokens for the last answer; cost is shown only when per-token rates are configured. Credits are not exposed unless the provider supplies a real balance.</div></aside>
   <section className="min-w-0"><div className="border border-[#1a2330] rounded-lg min-h-[58vh] p-4 space-y-3">{messages.length===0&&<div className="opacity-50 py-6">Ask Kontrol about Cyclothone, authorized internal evidence, or current public research.</div>}{messages.map((m,i)=><div key={m.created_at?m.created_at+"-"+i:i} className={m.role==="user"?"text-right":""}><div className="inline-block max-w-full md:max-w-3xl border border-[#1a2330] rounded px-3 py-2 text-left whitespace-pre-wrap"><div>{m.content}</div>{m.citations && m.citations.length>0 &&<div className="text-xs opacity-70 mt-2 flex flex-wrap gap-3">{m.citations.map((c:any,j:number)=><span key={j}>{typeof c.url==="string"&&(c.url.startsWith("https://")||c.url.startsWith("http://"))?<a className="underline text-sky-300" href={c.url} target="_blank" rel="noopener noreferrer">{c.title||c.url}</a>:<span>[{c.kind}:{String(c.id).slice(0,8)}]</span>}</span>)}</div>}</div></div>)}{busy&&<div className="opacity-60">Kontrol is working…</div>}</div><div className="flex gap-2 mt-3"><input className="flex-1 min-w-0 border border-[#263446] bg-transparent rounded px-3 py-3" value={input} onChange={e=>setInput(e.target.value)} onKeyDown={e=>e.key==="Enter"&&!e.shiftKey&&send()} placeholder="Ask Kontrol about Cyclothone…" /><button className="border border-sky-700 rounded px-5" onClick={send} disabled={busy||!input.trim()}>{busy?"Working…":"Send"}</button></div>{error&&<div role="alert" className="text-sm mt-2 text-amber-300">{error}</div>}<div className="text-xs opacity-50 mt-3">Saved conversations can be reopened from the left panel. Case-bound investigation chats remain scoped separately. {usage?.provider&&<span> Last provider: {usage.provider}{usage.model?"/"+usage.model:""} · measured usage only.</span>}</div></section>
  </div></div></main>;
}
