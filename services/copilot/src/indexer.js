import {createClient} from "@supabase/supabase-js";
import {embed} from "./engine.js";
import {createHash} from "node:crypto";
const sb=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_SERVICE_ROLE_KEY,{auth:{persistSession:false,autoRefreshToken:false}});
const hash=s=>createHash("sha256").update(s).digest("hex");
async function indexTable(table,kind,columns,tenantColumn="tenant_id"){
  const since=new Date(Date.now()-10*60_000).toISOString();
  const {data,error}=await sb.from(table).select(columns).gte("updated_at",since).limit(500);
  if(error)return;
  for(const row of data||[]){
    const text=JSON.stringify(row);
    const embedding=await embed(text);
    await sb.from("mdi_embeddings").upsert({tenant_id:row[tenantColumn],entity_kind:kind,entity_id:row.id,content:text,content_hash:hash(text),embedding,model:process.env.OLLAMA_EMBED_MODEL||"nomic-embed-text",updated_at:new Date().toISOString()},{onConflict:"tenant_id,entity_kind,entity_id,model"});
  }
}
export async function reindex(){
  await indexTable("mdi_subjects","subject","id,tenant_id,kind,canonical,display,risk_band,attributes,updated_at");
  await indexTable("mdi_rf_threats","threat","id,tenant_id,threat_type,severity,confidence,explanation,created_at,updated_at");
  await indexTable("mdi_payments","payment","id,tenant_id,subject_id,occurred_at,amount,currency,status,channel,source_country,destination_country,updated_at");
}
if(process.env.MDI_COPILOT_INDEXER==="true"){await reindex().catch(console.error);setInterval(()=>reindex().catch(console.error),300000);}
