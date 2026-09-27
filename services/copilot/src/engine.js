import { createClient } from "@supabase/supabase-js";
const sb=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_SERVICE_ROLE_KEY,{auth:{persistSession:false,autoRefreshToken:false}});
const OLLAMA=(process.env.OLLAMA_URL||"http://ollama:11434").replace(/\/$/,"");
const MODEL=process.env.OLLAMA_MODEL||"llama3.1:8b";
const EMBED_MODEL=process.env.OLLAMA_EMBED_MODEL||"nomic-embed-text";

async function embed(text){
  const r=await fetch(OLLAMA+"/api/embeddings",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({model:EMBED_MODEL,prompt:text})});
  if(!r.ok) throw new Error("embedding service unavailable");
  const j=await r.json();
  if(!Array.isArray(j.embedding)||j.embedding.length!==768) throw new Error("embedding dimension mismatch");
  return j.embedding;
}

const tools={
get_subject: async({tenant_id,canonical,kind})=>{const {data:subjects,error}=await sb.from("mdi_subjects").select("id,kind,canonical,display,risk_band,attributes").eq("kind",kind).eq("canonical",canonical).limit(1);if(error)throw error;const s=subjects?.[0];if(!s)return null;const {data:link}=await sb.from("mdi_subject_tenants").select("subject_id").eq("tenant_id",tenant_id).eq("subject_id",s.id).maybeSingle();return link?s:null;},
get_neighborhood: async({tenant_id,subject_id,hops=2})=>sb.rpc("mdi_neighborhood",{p_tenant_id:tenant_id,p_subject:subject_id,p_hops:Math.min(Math.max(Number(hops)||2,1),4),p_min_weight:0.1}),
get_risk_breakdown: async({tenant_id,subject_id})=>{const {data:link}=await sb.from("mdi_subject_tenants").select("subject_id").eq("tenant_id",tenant_id).eq("subject_id",subject_id).maybeSingle();if(!link)return null;return (await sb.from("mdi_risk_assessments").select("*").eq("subject_id",subject_id).order("computed_at",{ascending:false}).limit(1).maybeSingle()).data;},
get_payments: async({tenant_id,subject_id,days=30})=>{const {data:link}=await sb.from("mdi_subject_tenants").select("subject_id").eq("tenant_id",tenant_id).eq("subject_id",subject_id).maybeSingle();if(!link)return [];return (await sb.from("mdi_payments").select("id,occurred_at,amount,currency,status,channel,country_from,country_to").eq("subject_id",subject_id).gte("occurred_at",new Date(Date.now()-Math.min(Number(days)||30,365)*86400000).toISOString()).order("occurred_at",{ascending:false}).limit(100)).data||[];},
get_attribution: async({tenant_id,case_id})=>{const {data:caseRow}=await sb.from("crime_cases").select("id").eq("id",case_id).eq("tenant_id",tenant_id).maybeSingle();if(!caseRow)return [];return (await sb.from("mdi_attribution").select("id,actor_id,confidence,method,evidence,alternative_actors,computed_at").eq("case_id",case_id).order("computed_at",{ascending:false}).limit(3)).data||[];},
screen_sanctions: async({name,country})=>sb.rpc("mdi_screen_name",{p_name:name,p_threshold:0.75}),
simswap_hazard: async({tenant_id,subject_id})=>{const {data:link}=await sb.from("mdi_subject_tenants").select("subject_id").eq("tenant_id",tenant_id).eq("subject_id",subject_id).maybeSingle();if(!link)return null;return (await sb.rpc("mdi_simswap_hazard",{p_subject:subject_id})).data;},
rag_search: async({tenant_id,query,case_id})=>sb.rpc("mdi_rag_search",{p_tenant_id:tenant_id,p_query_embedding:await embed(query),p_case:case_id||null,p_kinds:null,p_k:15})
};

async function callModel(messages){
  if(process.env.OPENAI_API_KEY){
    const r=await fetch("https://api.openai.com/v1/chat/completions",{method:"POST",headers:{"content-type":"application/json",Authorization:`Bearer ${process.env.OPENAI_API_KEY}`},body:JSON.stringify({model:process.env.OPENAI_MODEL||"gpt-5.6-mini",messages,temperature:0.1,response_format:{type:"json_object"}})});
    if(r.ok){const j=await r.json();return j.choices?.[0]?.message?.content||"";}
  }
  const r=await fetch(OLLAMA+"/api/chat",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({model:MODEL,messages,stream:false,format:"json",options:{temperature:0.1,num_ctx:8192}})});
  if(!r.ok) throw new Error("LLM unavailable");
  const j=await r.json(); return j.message?.content||"";
}
function parseJson(s){try{return JSON.parse(s)}catch{return {answer:s}}}

export async function ask({tenant_id,thread_id,user_id,message,case_id=null}){
  if(!tenant_id||!thread_id||!user_id||!message?.trim()) throw new Error("invalid copilot request");
  const {data:thread}=await sb.from("mdi_copilot_threads").select("id,tenant_id,case_id").eq("id",thread_id).eq("tenant_id",tenant_id).maybeSingle();
  if(!thread){
    await sb.from("mdi_copilot_threads").insert({id:thread_id,tenant_id,case_id,actor_id:user_id}).throwOnError();
  }
  await sb.from("mdi_copilot_messages").insert({tenant_id,thread_id,role:"user",content:message.trim()}).throwOnError();
  const {data:history}=await sb.from("mdi_copilot_messages").select("role,content").eq("tenant_id",tenant_id).eq("thread_id",thread_id).order("created_at",{ascending:true}).limit(20);
  const system={role:"system",content:"You are Cyclothone MDI investigation copilot. Use only tool-returned facts. Never invent IDs, scores, actors, techniques, or events. A factual statement must be traceable to a citation. If evidence is insufficient, say so. You may request one tool at a time using JSON {tool,args}; otherwise return {answer,citations:[{kind,id}]}. Never authorize or execute security actions."};
  const messages=[system,...(history||[])];
  const calls=[]; const citations=[];
  for(let turn=0;turn<5;turn++){
    const parsed=parseJson(await callModel(messages));
    if(!parsed.tool){
      const answer=String(parsed.answer||"No supported answer was produced.");
      const safeCitations=Array.isArray(parsed.citations)?parsed.citations.filter(c=>c&&c.id&&c.kind):[];
      await sb.from("mdi_copilot_messages").insert({tenant_id,thread_id,role:"assistant",content:answer,citations:safeCitations,tool_calls:calls}).throwOnError();
      return {answer,citations:safeCitations,toolCalls:calls};
    }
    const fn=tools[parsed.tool]; if(!fn) throw new Error("unsupported tool");
    const result=await fn({...parsed.args,tenant_id});
    const data=result?.data??result;
    calls.push({name:parsed.tool,args:parsed.args,result:data});
    messages.push({role:"tool",content:JSON.stringify({tool:parsed.tool,result:data}).slice(0,50000)});
  }
  throw new Error("copilot tool loop limit reached");
}
export {embed};
