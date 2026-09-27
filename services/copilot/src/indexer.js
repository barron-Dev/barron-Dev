import {createClient} from "@supabase/supabase-js";
import {embed} from "./engine.js";
import {createHash} from "node:crypto";
const sb=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_SERVICE_ROLE_KEY,{auth:{persistSession:false,autoRefreshToken:false}});
const hash=s=>createHash("sha256").update(s).digest("hex");
async function put(tenantId,kind,row){
 if(!tenantId||!row?.id)return;
 const text=JSON.stringify(row); const embedding=await embed(text);
 await sb.from("mdi_embeddings").upsert({tenant_id:tenantId,entity_kind:kind,entity_id:row.id,content:text,content_hash:hash(text),embedding,model:process.env.OLLAMA_EMBED_MODEL||"nomic-embed-text",updated_at:new Date().toISOString()},{onConflict:"tenant_id,entity_kind,entity_id,model"}).throwOnError();
}
async function reindexSubjects(since){
 const {data,error}=await sb.from("mdi_subjects").select("id,kind,canonical,display,risk_band,attributes,last_seen").gte("last_seen",since).limit(500);if(error)throw error;
 for(const s of data||[]){const {data:links}=await sb.from("mdi_subject_tenants").select("tenant_id").eq("subject_id",s.id);for(const l of links||[])await put(l.tenant_id,"subject",s);}
}
async function reindexThreats(since){
 const {data,error}=await sb.from("mdi_rf_threats").select("id,observation_id,threat_type,severity,confidence,explanation,created_at").gte("created_at",since).limit(500);if(error)return;
 for(const t of data||[]){const {data:obs}=await sb.from("mdi_rf_observations").select("subject_id").eq("id",t.observation_id).maybeSingle();if(!obs?.subject_id)continue;const {data:links}=await sb.from("mdi_subject_tenants").select("tenant_id").eq("subject_id",obs.subject_id);for(const l of links||[])await put(l.tenant_id,"threat",t);}
}
async function reindexPayments(since){
 const {data,error}=await sb.from("mdi_payments").select("id,subject_id,occurred_at,amount,currency,status,channel,source_country,destination_country").gte("occurred_at",since).limit(500);if(error)return;
 for(const p of data||[]){const {data:links}=await sb.from("mdi_subject_tenants").select("tenant_id").eq("subject_id",p.subject_id);for(const l of links||[])await put(l.tenant_id,"payment",p);}
}
export async function reindex(){const since=new Date(Date.now()-10*60_000).toISOString();await reindexSubjects(since);await reindexThreats(since);await reindexPayments(since);}
