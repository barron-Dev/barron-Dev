"use client";
import { useEffect,useState } from "react";

type Identity={id:string;kind:string;full_name:string;photo_phash?:string|null};

export default function LensPage(){
 const [identities,setIdentities]=useState<Identity[]>([]);
 const [selected,setSelected]=useState("");
 const [file,setFile]=useState<File|null>(null);
 const [busy,setBusy]=useState(false);
 const [message,setMessage]=useState("");
 async function load(){const r=await fetch("/api/proxy/v1/lens/identities"); if(r.ok)setIdentities(await r.json());}
 useEffect(()=>{load()},[]);
 async function enroll(){
  if(!selected||!file)return;
  setBusy(true);setMessage("");
  try{const body=new FormData();body.append("photo",file);
   const r=await fetch("/api/proxy/v1/lens/identities/"+selected+"/photo",{method:"POST",body});
   const data=await r.json().catch(()=>({}));
   if(!r.ok)throw new Error(data.detail||"Enrollment failed");
   setMessage("Photo fingerprint enrolled. The original image was not stored.");
   await load();
  }catch(e){setMessage(e instanceof Error?e.message:"Enrollment failed")}
  finally{setBusy(false)}
 }
 return <div className="p-6 space-y-5 max-w-5xl">
  <header><h1 className="text-2xl font-semibold">Cyclothone Lens</h1><p className="text-xs text-text-tertiary mt-1">Identity monitoring and privacy-preserving photo fingerprints.</p></header>
  <section className="card p-5 space-y-4">
   <div className="text-sm font-medium">Photo fingerprint enrollment</div>
   <p className="text-xs text-text-tertiary">Upload a reference photo for perceptual matching. Lens stores only a fingerprint, not the original image.</p>
   <div className="grid md:grid-cols-2 gap-3">
    <select value={selected} onChange={e=>setSelected(e.target.value)} className="h-10 rounded-md border border-border-subtle bg-surface px-3 text-sm">
     <option value="">Select identity…</option>{identities.map(i=><option key={i.id} value={i.id}>{i.full_name} · {i.kind}</option>)}
    </select>
    <input type="file" accept="image/jpeg,image/png,image/webp" onChange={e=>setFile(e.target.files?.[0]??null)} className="text-xs"/>
   </div>
   <button disabled={!selected||!file||busy} onClick={enroll} className="h-9 px-4 rounded-md bg-accent text-text-inverse text-sm disabled:opacity-50">{busy?"Enrolling…":"Enroll photo fingerprint"}</button>
   {message&&<div className="text-xs text-text-tertiary">{message}</div>}
  </section>
  <section className="card overflow-hidden"><table className="w-full text-sm"><thead className="bg-surface text-text-tertiary text-[10px] uppercase"><tr><th className="text-left px-4 py-2">Identity</th><th className="text-left px-4 py-2">Kind</th><th className="text-left px-4 py-2">Photo fingerprint</th></tr></thead><tbody>
   {identities.map(i=><tr key={i.id} className="border-t border-border-subtle"><td className="px-4 py-2">{i.full_name}</td><td className="px-4 py-2 text-xs">{i.kind}</td><td className="px-4 py-2 font-mono text-[10px]">{i.photo_phash?"enrolled":"not enrolled"}</td></tr>)}
  </tbody></table></section>
 </div>
}
