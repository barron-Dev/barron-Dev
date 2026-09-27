import http from "node:http";
const token=process.env.MDI_COPILOT_INTERNAL_TOKEN;
const server=http.createServer((req,res)=>{if(req.url==="/health"){res.writeHead(200,{"content-type":"application/json"});return res.end(JSON.stringify({status:"ok"}));}res.writeHead(404);res.end();});
server.listen(Number(process.env.PORT||8080));
