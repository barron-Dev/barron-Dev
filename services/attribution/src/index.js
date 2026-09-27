import {syncCti} from "./cti.js";
import {combine} from "./engine.js";

const SUPABASE_URL=required("SUPABASE_URL").replace(/\/$/,"");
const SUPABASE_KEY=required("SUPABASE_SERVICE_ROLE_KEY");
const INTERVAL=Number(process.env.MDI_ATTRIBUTION_INTERVAL_MS||86400000);

function required(name){const v=process.env[name];if(!v)throw new Error(`missing_${name}`);return v;}

async function sb(path,options={}){
  const res=await fetch(`${SUPABASE_URL}/rest/v1/${path}`,{
    ...options,
    headers:{apikey:SUPABASE_KEY,Authorization:`Bearer ${SUPABASE_KEY}`,...(options.headers||{})}
  });
  if(!res.ok) throw new Error(`supabase_${res.status}:${await res.text()}`);
  return res.status===204?null:res.json();
}

async function attributeCase(caseId){
  const rows=await sb(`mdi_case_ttps?select=technique_id,confidence&case_id=eq.${encodeURIComponent(caseId)}`);
  const caseTtps=[...new Set((rows??[]).filter(r=>Number(r.confidence)>0.5).map(r=>r.technique_id))];
  if(!caseTtps.length) return null;
  const actors=await sb("mdi_threat_actors?select=id,actor_id,name");
  const links=await sb("mdi_actor_ttps?select=actor_id,technique_id,confidence");
  const map=new Map((actors??[]).map(a=>[a.id,a]));
  const sets=new Map();
  for(const r of links??[]){
    if(Number(r.confidence)<=0.5) continue;
    if(!sets.has(r.actor_id)) sets.set(r.actor_id,new Set());
    sets.get(r.actor_id).add(r.technique_id);
  }
  const candidates=combine(caseTtps,[...sets.entries()].map(([id,ttps])=>({id,actorId:map.get(id)?.actor_id??id,name:map.get(id)?.name??id,ttps})),Math.max((await sb("mdi_attack_mobile?select=technique_id")).length,1));
  if(!candidates.length) return null;
  const top=candidates[0];
  await sb("mdi_attribution",{
    method:"POST",
    headers:{"Content-Type":"application/json",Prefer:"return=minimal"},
    body:JSON.stringify({case_id:caseId,actor_id:top.actorUuid??null,confidence:Math.max(0,Math.min(1,top.combined)),method:"ttp_jaccard+naive_bayes",evidence:{caseTtps,sharedTtps:top.sharedTtps,jaccard:top.jaccard,bayes:top.bayesProb},alternative_actors:candidates.slice(1,5),computed_at:new Date().toISOString()})
  });
  return {caseId,candidates:candidates.slice(0,10),caseTtps};
}

async function run(){
  try{console.log(JSON.stringify({component:"mdi-attribution",event:"cti_sync",result:await syncCti()}));}
  catch(error){console.error(JSON.stringify({component:"mdi-attribution",event:"cti_sync_failed",error:String(error)}));}
  const cases=await sb("mdi_case_ttps?select=case_id&order=observed_at.desc&limit=100");
  const ids=[...new Set((cases??[]).map(r=>r.case_id))];
  for(const id of ids){
    try{const result=await attributeCase(id);if(result)console.log(JSON.stringify({component:"mdi-attribution",event:"case_attributed",result}));}
    catch(error){console.error(JSON.stringify({component:"mdi-attribution",caseId:id,error:String(error)}));}
  }
}

await run();
setInterval(()=>void run(),INTERVAL);