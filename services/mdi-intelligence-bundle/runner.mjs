import {spawn} from "node:child_process";import http from "node:http";
const port=Number(process.env.PORT||8080),env={...process.env,PORT:String(port)};
const a=spawn("node",["/app/copilot/src/index.js"],{env,stdio:"inherit"});const b=spawn("node",["/app/compliance/src/index.js"],{env,stdio:"inherit"});
a.on("exit",c=>process.exit(c??1));b.on("exit",c=>process.exit(c??1));
const s=http.createServer((q,r)=>{r.writeHead(q.url==="/health"?200:404,{"content-type":"application/json"});r.end(JSON.stringify(q.url==="/health"?{status:"ok",service:"mdi-intelligence-bundle",workers:["copilot","compliance"]}:{error:"not_found"}));});s.listen(port,"0.0.0.0");