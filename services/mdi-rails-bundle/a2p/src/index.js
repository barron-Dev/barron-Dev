import http from "node:http";
const port=Number(process.env.PORT||8080);
function json(res,status,body){res.writeHead(status,{"content-type":"application/json"});res.end(JSON.stringify(body));}
const server=http.createServer((req,res)=>{
 if(req.url==="/health")return json(res,200,{status:"ok",service:"mdi-a2p-verifier"});
 if(req.method==="POST"&&req.url==="/verify"){let b="";req.on("data",x=>b+=x);req.on("end",()=>{try{const p=JSON.parse(b||"{}");json(res,200,{verified:false,status:"pending_crypto",reason:"ed25519_verification_boundary",nonce:p.nonce??null});}catch{json(res,400,{error:"invalid_json"});}});return}
 json(res,404,{error:"not_found"});
});server.listen(port,"0.0.0.0");