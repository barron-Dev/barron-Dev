import http from "node:http";
import {ask} from "./engine.js";
const token=process.env.MDI_COPILOT_INTERNAL_TOKEN;
if(!token) throw new Error("MDI_COPILOT_INTERNAL_TOKEN is required");
const server=http.createServer(async(req,res)=>{
  if(req.method!=="POST"||req.url!=="/ask"){res.writeHead(404);return res.end();}
  if(req.headers.authorization!==`Bearer ${token}`){res.writeHead(401);return res.end(JSON.stringify({error:"unauthorized"}));}
  try{let body="";for await(const chunk of req) body+=chunk;
    const result=await ask(JSON.parse(body));
    res.writeHead(200,{"content-type":"application/json"});res.end(JSON.stringify(result));
  }catch(e){res.writeHead(400,{"content-type":"application/json"});res.end(JSON.stringify({error:e instanceof Error?e.message:"copilot_failed"}));}
});
server.listen(Number(process.env.PORT||8080));
