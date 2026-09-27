import { createClient } from "@supabase/supabase-js";

const url = process.env.SUPABASE_URL;
const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
if (!url || !key) throw new Error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required");
const sb = createClient(url,key,{auth:{persistSession:false,autoRefreshToken:false}});
const intervalMs=Number(process.env.MDI_COMPLIANCE_INTERVAL_MS||900000);

async function auditTenant(tenantId){
  const checks=["mdi_audit_retention","mdi_audit_lawful_basis","mdi_audit_cross_border","mdi_dsar_sla_breach"];
  for(const fn of checks){
    const {data,error}=await sb.rpc(fn,{p_tenant_id:tenantId});
    if(error) throw new Error(fn+": "+error.message);
    for(const row of data||[]){
      const subjectId=row.subject_id??null;
      const jurisdiction=row.jurisdiction??"MULTI";
      await sb.from("mdi_compliance_findings").insert({
        tenant_id:tenantId,jurisdiction,subject_id:subjectId,case_id:row.case_id??null,
        severity:row.severity,finding:fn,evidence:row
      }).throwOnError();
    }
  }
}

async function listTenants(){
  const {data,error}=await sb.from("mdi_subjects").select("tenant_id").not("tenant_id","is",null).limit(10000);
  if(error) throw error;
  return [...new Set((data||[]).map(x=>x.tenant_id).filter(Boolean))];
}
async function cycle(){
  for(const tenantId of await listTenants()) await auditTenant(tenantId);
}
console.log("MDI compliance worker ready; interval="+intervalMs);
await cycle().catch(console.error);
setInterval(()=>cycle().catch(console.error),intervalMs);
