import http from "node:http";
import {ask} from "./engine.js";
import {CopilotRequestError, responseForCopilotError} from "./copilot-errors.js";
import {reindex} from "./indexer.js";
const token=process.env.MDI_COPILOT_INTERNAL_TOKEN;
if(!token) throw new Error("MDI_COPILOT_INTERNAL_TOKEN is required");
const server=http.createServer(async(req,res)=>{
  if(req.url==="/health"){res.writeHead(200,{"content-type":"application/json"});return res.end(JSON.stringify({status:"ok"}));}
  if(req.method!=="POST"||req.url!=="/ask"){res.writeHead(404);return res.end();}
  if(req.headers.authorization!==`Bearer ${token}`){res.writeHead(401);return res.end(JSON.stringify({error:"unauthorized"}));}
  try{let body="";for await(const chunk of req) body+=chunk;
    if(body.length>100000) throw new CopilotRequestError();
    let payload; try { payload=JSON.parse(body); } catch { throw new CopilotRequestError(); }
    if(!payload||typeof payload!=="object"||Array.isArray(payload)) throw new CopilotRequestError();
    const result=await ask(payload);
    res.writeHead(200,{"content-type":"application/json"});res.end(JSON.stringify(result));
  }catch(e){const response=responseForCopilotError(e);res.writeHead(response.statusCode,{"content-type":"application/json"});res.end(JSON.stringify(response.body));}
});
server.listen(Number(process.env.PORT||8080));
if(process.env.MDI_COPILOT_INDEXER==="true"){reindex().catch(console.error);setInterval(()=>reindex().catch(console.error),300000);}
