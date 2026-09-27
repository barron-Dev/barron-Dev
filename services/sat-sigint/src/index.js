const SUPABASE_URL = required("SUPABASE_URL").replace(/\/$/,"");
const SUPABASE_KEY = required("SUPABASE_SERVICE_ROLE_KEY");
const USER_AGENT = process.env.MDI_SAT_USER_AGENT || "Cyclothone-MDI/1.0";
const GROUPS = (process.env.MDI_CELESTRAK_GROUPS || "active,weather,noaa,science,geo,starlink")
  .split(",").map(s=>s.trim()).filter(Boolean);
const PERIOD_MS = Number(process.env.MDI_SAT_SYNC_INTERVAL_MS || 7200000);

function required(name){const v=process.env[name];if(!v)throw new Error(`missing_${name}`);return v;}

async function upsertRows(rows){
  for(let i=0;i<rows.length;i+=500){
    const batch=rows.slice(i,i+500);
    const res=await fetch(`${SUPABASE_URL}/rest/v1/mdi_satellites?on_conflict=norad_id`,{
      method:"POST",
      headers:{
        apikey:SUPABASE_KEY,
        Authorization:`Bearer ${SUPABASE_KEY}`,
        "Content-Type":"application/json",
        Prefer:"resolution=merge-duplicates,return=minimal"
      },
      body:JSON.stringify(batch)
    });
    if(!res.ok) throw new Error(`supabase_upsert_${res.status}:${await res.text()}`);
  }
}

async function syncGroup(group){
  const url=`https://celestrak.org/NORAD/elements/gp.php?GROUP=${encodeURIComponent(group)}&FORMAT=JSON`;
  const res=await fetch(url,{headers:{"user-agent":USER_AGENT,accept:"application/json"}});
  if(!res.ok) throw new Error(`celestrak_${group}_${res.status}`);
  const data=await res.json();
  const now=new Date().toISOString();
  const rows=[];
  for(const s of Array.isArray(data)?data:[]){
    const id=Number(s.NORAD_CAT_ID ?? s.OBJECT_ID);
    if(!Number.isInteger(id) || id<1 || id>2147483647) continue;
    rows.push({
      norad_id:id,
      name:String(s.OBJECT_NAME ?? `NORAD-${id}`).trim(),
      intl_designator:s.OBJECT_ID ?? null,
      purpose:null,
      tle_line1:null,
      tle_line2:null,
      epoch:s.EPOCH ?? null,
      inclination:s.INCLINATION ?? null,
      raan:s.RA_OF_ASC_NODE ?? null,
      eccentricity:s.ECCENTRICITY ?? null,
      argp:s.ARG_OF_PERICENTER ?? null,
      mean_anomaly:s.MEAN_ANOMALY ?? null,
      mean_motion:s.MEAN_MOTION ?? null,
      bstar:s.BSTAR ?? null,
      updated_at:now
    });
  }
  await upsertRows(rows);
  return {group,count:rows.length};
}

async function syncAll(){
  const results=[];
  for(const group of GROUPS){
    try{results.push(await syncGroup(group));}
    catch(error){console.error(JSON.stringify({component:"mdi-sat-sigint",group,error:String(error)}));}
  }
  console.log(JSON.stringify({component:"mdi-sat-sigint",event:"sync_complete",results,at:new Date().toISOString()}));
}

await syncAll();
setInterval(()=>void syncAll(),PERIOD_MS);