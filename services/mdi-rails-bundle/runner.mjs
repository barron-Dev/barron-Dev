import {spawn} from "node:child_process";import http from "node:http";
const port=Number(process.env.PORT||8080),env={...process.env};
const children=[];
for(const p of ["/app/a2p/src/index.js","/app/chain/src/index.js"]){const c=spawn("node",[p],{env,stdio:"inherit"});children.push(c);c.on("exit",code=>process.exit(code??1));}
const s=http.createServer((q,r)=>{r.writeHead(q.url==="/health"?200:404,{"content-type":"application/json"});r.end(JSON.stringify(q.url==="/health"?{status:"ok",service:"mdi-rails-bundle",workers:["a2p","chain"]}:{error:"not_found"}));});s.listen(port,"0.0.0.0");