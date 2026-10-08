import {spawn} from "node:child_process";import http from "node:http";
const port=Number(process.env.PORT||8080),env={...process.env};
const a=spawn("node",["/app/rf-worker/src/index.js"],{env,stdio:"inherit"});
const b=spawn("node",["/app/voice-worker/src/index.js"],{env,stdio:"inherit"});
const fail=c=>process.exit(c??1);a.on("exit",fail);b.on("exit",fail);
const s=http.createServer((q,r)=>{r.writeHead(q.url==="/health"?200:404,{"content-type":"application/json"});r.end(JSON.stringify(q.url==="/health"?{status:"ok",service:"mdi-rf-bundle",workers:["rf","voice"]}:{error:"not_found"}));});
s.listen(port,"0.0.0.0");