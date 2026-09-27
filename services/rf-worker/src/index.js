const url=(process.env.SUPABASE_URL||"").replace(/\/$/,"");const key=process.env.SUPABASE_SERVICE_ROLE_KEY;
if(!url||!key) throw new Error("missing_supabase_configuration");
const headers={apikey:key,Authorization:`Bearer ${key}`,Accept:"application/json"};
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function get(path){const r=await fetch(url+"/rest/v1/"+path,{headers});if(!r.ok)throw new Error(`supabase_${r.status}`);return r.json();}
async function post(path,row){const r=await fetch(url+"/rest/v1/"+path,{method:"POST",headers:{...headers,"Content-Type":"application/json",Prefer:"return=minimal"},body:JSON.stringify(row)});if(!r.ok)throw new Error(`supabase_${r.status}:${await r.text()}`);}
async function detect(){const since=new Date(Date.now()-120000).toISOString();const rows=await get("mdi_rf_observations?select=id,subject_id,radio,mcc,mnc,lac,cid,rx_level_dbm,ssid,bssid_hash,gnss_sats,spoof_flag,observed_at&observed_at=gt."+encodeURIComponent(since)+"&limit=500");
for(const o of rows){
 const threats=[];
 if(o.radio==="cellular"&&o.rx_level_dbm!=null&&Number(o.rx_level_dbm)>-65&&!o.mcc&&!o.mnc) threats.push(["imsi_catcher",4,.6,"rf_cell_identity_gap_v1"]);
 if(o.radio==="wifi"&&o.ssid&&/^.{0,2}(free|wifi|airport|hotel|company|corp)/i.test(o.ssid)&&Number(o.rssi??-100)>-55) threats.push(["rogue_ap",3,.55,"rf_open_brand_ssid_v1"]);
 if(o.radio==="gnss"&&(o.spoof_flag||Number(o.gnss_sats??99)<4)) threats.push([o.spoof_flag?"gps_spoofer":"gps_jammer",4,.7,"gnss_integrity_v1"]);
 for(const [type,severity,confidence,algorithm] of threats) await post("mdi_rf_threats",{observation_id:o.id,threat_type:type,severity,confidence,algorithm,explanation:{source:"consented_rf_observation"}});
}}
for(;;){try{await detect()}catch(e){console.error(JSON.stringify({component:"mdi-rf-worker",error:String(e)}));}await sleep(60000);}