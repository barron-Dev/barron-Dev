import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2";

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const serviceRole = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const admin = createClient(supabaseUrl, serviceRole, { auth: { persistSession: false } });

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
  status, headers: { "content-type": "application/json" }
});

async function gleif(lei: string) {
  const normalized = lei.trim().toUpperCase();
  if (!/^[A-Z0-9]{20}$/.test(normalized)) throw new Error("Invalid LEI");
  const response = await fetch(`https://api.gleif.org/api/v1/lei-records/${normalized}`, {
    headers: { "accept": "application/vnd.api+json", "user-agent": "Cyclothone-GIRIL/1.0" }
  });
  if (response.status === 404) return { status: "NOT_VERIFIED", payload: null };
  if (!response.ok) return { status: "UNAVAILABLE", payload: null };
  const payload = await response.json();
  const data = payload?.data;
  const record = Array.isArray(data) ? (data.length === 1 ? data[0] : null) : data;
  if (!record) return { status: "MANUAL_REVIEW", payload };
  const attrs = record?.attributes ?? {};
  const entity = attrs?.entity ?? {};
  const verified = attrs?.lei === normalized && attrs?.entityStatus === "ACTIVE";
  return {
    status: verified ? "VERIFIED" : "NOT_VERIFIED",
    payload: {
      lei: attrs?.lei ?? null,
      legal_name: entity?.legalName?.name ?? null,
      entity_status: attrs?.entityStatus ?? null,
      country: entity?.legalAddress?.country ?? null,
      source: "GLEIF_LEI"
    }
  };
}

Deno.serve(async (req) => {
  if (req.method !== "POST") return json({ error: "method_not_allowed" }, 405);
  const auth = req.headers.get("authorization") ?? "";
  if (!auth.toLowerCase().startsWith("bearer ")) return json({ error: "authentication_required" }, 401);
  const token = auth.slice(7).trim();
  const { data: userData, error: userError } = await admin.auth.getUser(token);
  if (userError || !userData.user) return json({ error: "authentication_required" }, 401);
  const userId = userData.user.id;

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return json({ error: "invalid_json" }, 400); }

  const name = String(body.name ?? "").trim();
  const email = String(body.email ?? "").trim().toLowerCase();
  const phone = String(body.phone ?? "").trim();
  const kind = body.subject_kind ? String(body.subject_kind) : null;
  const country = body.country ? String(body.country).trim().toUpperCase() : null;
  const lei = body.lei ? String(body.lei).trim().toUpperCase() : null;

  if (!name || name.length > 240) return json({ error: "invalid_name" }, 400);
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || email.length > 320) return json({ error: "invalid_email" }, 400);
  if (!/^\+?[0-9\s().-]{7,32}$/.test(phone)) return json({ error: "invalid_phone" }, 400);

  const { data: existing } = await admin.from("giril_onboarding_cases").select("id").eq("applicant_user_id", userId).not("state","in","(ADMITTED,REJECTED)").maybeSingle();
  let caseId = existing?.id;
  if (caseId) {
    const { error } = await admin.from("giril_onboarding_cases").update({
      requested_name:name,email,phone,subject_kind:kind,country_iso2:country,state:"VERIFYING",updated_at:new Date().toISOString()
    }).eq("id",caseId).eq("applicant_user_id",userId);
    if (error) return json({ error:"case_update_failed" },500);
  } else {
    const { data,error } = await admin.from("giril_onboarding_cases").insert({
      applicant_user_id:userId,requested_name:name,email,phone,subject_kind:kind,country_iso2:country,state:lei?"VERIFYING":"COLLECTING"
    }).select("id").single();
    if (error) return json({ error:"case_create_failed",detail:error.message },500);
    caseId=data.id;
  }

  let verification:any=null;
  if (lei) {
    const result=await gleif(lei);
    const source=await admin.from("giril_ref_sources").select("id").eq("source_key","GLEIF_LEI").maybeSingle();
    if (!source.data?.id) return json({error:"gleif_source_not_registered"},500);
    const digest=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(lei));
    const hash=Array.from(new Uint8Array(digest)).map(x=>x.toString(16).padStart(2,"0")).join("");
    const {data:check,error}=await admin.from("giril_verification_checks").insert({
      onboarding_case_id:caseId,check_type:"COMPANY_REGISTRY",target_hash:hash,source_id:source.data.id,
      status:result.status,verifier_version:"giril-gleif-v1",verification_method:"GLEIF_LEI_API",
      completed_at:new Date().toISOString(),metadata:result.payload??{reason:result.status}
    }).select("id,status").single();
    if(error) return json({error:"verification_record_failed",detail:error.message},500);
    verification=check;
    await admin.from("giril_onboarding_cases").update({
      state:result.status==="VERIFIED"?"CONTROL_REVIEW":"MANUAL_REVIEW",updated_at:new Date().toISOString()
    }).eq("id",caseId);
  }

  let organization:any=null;
  if(kind) {
    const map:any={COMPANY:"company",GOVERNMENT:"government",SECURITY_PROVIDER:"security_provider",DEVELOPER:"developer",PARTNER:"partner",INDIVIDUAL:"individual",OTHER:"client"};
    const organizationType=map[kind];
    const existingOrg=await admin.from("customer_organizations").select("id,admission_status,verification_status").eq("owner_user_id",userId).limit(1).maybeSingle();
    if(existingOrg.data) organization=existingOrg.data;
    else {
      const {data:org,error:orgError}=await admin.from("customer_organizations").insert({
        owner_user_id:userId,organization_type:organizationType,legal_name:name,country_code:country,
        verification_status:verification?.status==="VERIFIED"?"business_verified":"unverified",admission_status:"pending"
      }).select("id,admission_status,verification_status").single();
      if(orgError) return json({error:"organization_create_failed",detail:orgError.message},500);
      organization=org;
      await admin.from("organization_members").insert({organization_id:org.id,user_id:userId,role:"owner",status:"active"});
      await admin.from("organization_admissions").insert({organization_id:org.id,requested_by:userId,status:"pending",submitted_at:new Date().toISOString()});
    }
  }
  return json({status:"accepted",onboarding_case_id:caseId,verification,organization});
});