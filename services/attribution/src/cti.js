const SUPABASE_URL = required("SUPABASE_URL").replace(/\/$/,"");
const SUPABASE_KEY = required("SUPABASE_SERVICE_ROLE_KEY");
const GAPMATRIX_KEY = process.env.GAPMATRIX_API_KEY || "";
const GAPMATRIX_BASE = "https://incidentbuddy.ai/api/v1";
const RANSOMWARE_BASE = process.env.RANSOMWARE_LIVE_BASE_URL || "https://api.ransomware.live/v2";

function required(name){const v=process.env[name];if(!v)throw new Error(`missing_${name}`);return v;}

async function sb(path,options={}){
  const res=await fetch(`${SUPABASE_URL}/rest/v1/${path}`,{
    ...options,
    headers:{apikey:SUPABASE_KEY,Authorization:`Bearer ${SUPABASE_KEY}`},...(options.headers||{})}
  });
  if(!res.ok) throw new Error(`supabase_${res.status}:${await res.text()}`);
  return res.status===204?null:res.json();
}

async function syncGapMatrixActor(actorId){
  if(!GAPMATRIX_KEY) return {skipped:"GAPMATRIX_API_KEY_missing"};
  const res=await fetch(`${GAPMATRIX_BASE}/actors/${encodeURIComponent(actorId)}`,{
    headers:{"X-API-Key":GAPMATRIX_KEY,accept:"application/json"}
  });
  if(!res.ok) throw new Error(`gapmatrix_${res.status}`);
  const a=await res.json();
  const actorRows=await sb("mdi_threat_actors?on_conflict=actor_id",{
    method:"POST",
    headers:{"Content-Type":"application/json",Prefer:"resolution=merge-duplicates,return=representation"},
    body:JSON.stringify({actor_id:a.actor_id??actorId,name:a.name??actorId,aliases:a.aliases??[],origin_country:a.origin_country??null,motivation:a.motivation??null,sophistication:a.sophistication??null,first_seen:a.first_seen??null,last_seen:a.last_seen??null,target_sectors:a.target_sectors??[],target_countries:a.target_countries??[],sources:["gapmatrix"],metadata:a,updated_at:new Date().toISOString()})
  });
  const actor=actorRows?.[0];
  if(!actor) return {actorId,stored:false};
  let mapped=0;
  for(const t of a.ttps??a.techniques??[]){
    const techniqueId=t.technique_id??t.id;
    if(!techniqueId) continue;
    const known=await sb(`mdi_attack_mobile?select=technique_id&technique_id=eq.${encodeURIComponent(techniqueId)}&limit=1`);
    if(!known?.length) continue;
    await sb("mdi_actor_ttps?on_conflict=actor_id,technique_id",{
      method:"POST",
      headers:{"Content-Type":"application/json",Prefer:"resolution=merge-duplicates,return=minimal"},
      body:JSON.stringify({actor_id:actor.id,technique_id:techniqueId,confidence:Number(t.confidence??0.7),source:"gapmatrix",evidence:t,last_observed:new Date().toISOString()})
    });
    mapped++;
  }
  return {actorId,stored:true,mapped};
}

async function syncRansomwareGroups(){
  const res=await fetch(`${RANSOMWARE_BASE}/groups`,{headers:{accept:"application/json"}});
  if(!res.ok) throw new Error(`ransomware_live_${res.status}`);
  const payload=await res.json();
  const groups=Array.isArray(payload)?payload:(payload.groups??[]);
  let stored=0;
  for(const g of groups){
    const actorId=String(g.name??g.slug??"").trim();
    if(!actorId) continue;
    await sb("mdi_threat_actors?on_conflict=actor_id",{
      method:"POST",
      headers:{"Content-Type":"application/json",Prefer:"resolution=merge-duplicates,return=minimal"},
      body:JSON.stringify({actor_id:actorId,name:actorId,aliases:g.aliases??[],motivation:"financial",target_sectors:g.sectors??[],target_countries:g.countries??[],sources:["ransomware.live"],metadata:g,updated_at:new Date().toISOString()})
    });
    stored++;
  }
  return stored;
}

export async function syncCti(){
  const actorIds=(process.env.MDI_GAPMATRIX_ACTORS||"APT28,Lazarus,FIN7").split(",").map(s=>s.trim()).filter(Boolean);
  const gap=[];
  for(const id of actorIds){
    try{gap.push(await syncGapMatrixActor(id));}
    catch(error){console.error(JSON.stringify({component:"mdi-attribution",source:"gapmatrix",actorId:id,error:String(error)}));}
  }
  let ransomware=0;
  try{ransomware=await syncRansomwareGroups();}
  catch(error){console.error(JSON.stringify({component:"mdi-attribution",source:"ransomware.live",error:String(error)}));}
  return {gap,ransomware};
}