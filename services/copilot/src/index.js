import http from "node:http";
import {URL} from "node:url";
import {ask} from "./engine.js";
import {CopilotRequestError, responseForCopilotError} from "./copilot-errors.js";
import {reindex} from "./indexer.js";
import {assertThreadOwnership} from "./thread-ownership.js";
import {createClient} from "@supabase/supabase-js";
const token=process.env.MDI_COPILOT_INTERNAL_TOKEN;
if(!token) throw new Error("MDI_COPILOT_INTERNAL_TOKEN is required");
const sb=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_SERVICE_ROLE_KEY,{auth:{persistSession:false,autoRefreshToken:false}});
function send(res,status,body){res.writeHead(status,{"content-type":"application/json"});res.end(JSON.stringify(body));}
function queryIdentity(url){const tenant_id=url.searchParams.get("tenant_id");const user_id=url.searchParams.get("user_id");if(!tenant_id||!user_id)return null;return {tenant_id,user_id};}
const server=http.createServer(async(req,res)=>{
  const url=new URL(req.url||"/","http://localhost");
  if(url.pathname==="/health"){return send(res,200,{status:"ok"});}
  if(req.headers.authorization!==`Bearer ${token}`){return send(res,401,{error:"unauthorized"});}
  try{
    if(req.method==="GET"&&url.pathname==="/threads"){
      const identity=queryIdentity(url);if(!identity)return send(res,400,{error:"invalid_history_request"});
      const limit=Math.max(1,Math.min(Number(url.searchParams.get("limit"))||50,100));
      const {data:threads,error}=await sb.from("mdi_copilot_threads").select("id,tenant_id,case_id,actor_id,created_at").eq("tenant_id",identity.tenant_id).eq("actor_id",identity.user_id).is("case_id",null).order("created_at",{ascending:false}).limit(limit);
      if(error)throw new Error("history_unavailable");
      if(!threads?.length)return send(res,200,{threads:[]});
      const ids=threads.map(t=>t.id);
      const {data:messages,error:messageError}=await sb.from("mdi_copilot_messages").select("thread_id,role,content,created_at").eq("tenant_id",identity.tenant_id).in("thread_id",ids).order("created_at",{ascending:false}).limit(1000);
      if(messageError)throw new Error("history_unavailable");
      const firstUser=new Map();
      for(const m of messages||[]){if(m.role==="user"&&!firstUser.has(m.thread_id))firstUser.set(m.thread_id,String(m.content||"").slice(0,120));}
      return send(res,200,{threads:threads.map(t=>({id:t.id,created_at:t.created_at,preview:firstUser.get(t.id)||"Saved conversation"}))});
    }
    const match=url.pathname.match(/^\/threads\/([0-9a-f-]{36})$/i);
    if(req.method==="GET"&&match){
      const identity=queryIdentity(url);if(!identity)return send(res,400,{error:"invalid_history_request"});
      const {data:thread,error}=await sb.from("mdi_copilot_threads").select("id,tenant_id,case_id,actor_id,created_at").eq("id",match[1]).eq("tenant_id",identity.tenant_id).maybeSingle();
      if(error)throw new Error("history_unavailable");
      if(!thread)return send(res,404,{error:"thread_not_found"});
      assertThreadOwnership(thread,{tenant_id:identity.tenant_id,user_id:identity.user_id,case_id:null});
      const {data:messages,error:messageError}=await sb.from("mdi_copilot_messages").select("role,content,citations,created_at").eq("tenant_id",identity.tenant_id).eq("thread_id",thread.id).order("created_at",{ascending:true}).limit(200);
      if(messageError)throw new Error("history_unavailable");
      return send(res,200,{thread:{id:thread.id,created_at:thread.created_at},messages:messages||[]});
    }
    if(req.method!=="POST"||url.pathname!=="/ask"){return send(res,404,{error:"not_found"});}
    let body="";for await(const chunk of req)body+=chunk;
    if(body.length>100000)throw new CopilotRequestError();
    let payload;try{payload=JSON.parse(body);}catch{throw new CopilotRequestError();}
    if(!payload||typeof payload!=="object"||Array.isArray(payload))throw new CopilotRequestError();
    const result=await ask(payload);
    return send(res,200,result);
  }catch(e){
    if(e?.name==="CopilotAccessError")return send(res,403,{error:"thread_access_denied"});
    if(e?.message==="history_unavailable")return send(res,503,{error:"copilot_history_unavailable"});
    const response=responseForCopilotError(e);return send(res,response.statusCode,response.body);
  }
});
server.listen(Number(process.env.PORT||8080));
if(process.env.MDI_COPILOT_INDEXER==="true"){reindex().catch(console.error);setInterval(()=>reindex().catch(console.error),300000);}
