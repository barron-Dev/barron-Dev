import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2";

const supabaseUrl=Deno.env.get("SUPABASE_URL")!;
const serviceRole=Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const admin=createClient(supabaseUrl,serviceRole,{auth:{persistSession:false}});
const json=(body:unknown,status=200)=>new Response(JSON.stringify(body),{status,headers:{"content-type":"application/json"}});

async function sha256(value:string){
 const d=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(value));
 return Array.from(new Uint8Array(d)).map(x=>x.toString(16).padStart(2,"0")).join("");
}
async function gleif(lei:string){
 const normalized=lei.trim().toUpperCase();
 if(!/^[A-Z0-9]{20}$/.test(normalized)) throw new Error("Invalid LEI");
 const response=await fetch(`https://api.gleif.org/api/v1/lei-records/${normalized}`,{headers:{"accept":"application/vnd.api+json","user-agent":"Cyclothone-GIRIL/1.0"}});
 if(response.status===404)return{status:"NOT_VERIFIED",payload:null};
 if(!response.ok)return{status:"UNAVAILABLE",payload:null};
 const payload=await response.json(); const data=payload?.data;
 const record=Array.isArray(data)?(data.length===1?data[0]:null):data;
 if(!record)return{status:"MANUAL_REVIEW",payload:null};
 const attrs=record?.attributes??{}; const entity=attrs?.entity??{};
 const verified=attrs?.lei===normalized&&attrs?.entityStatus==="ACTIVE";
 return{status:verified?"VERIFIED":"NOT_VERIFIED",payload:{lei:attrs?.lei??null,legal_name:entity?.legalName?.name??null,entity_status:attrs?.entityStatus??null,country:entity?.legalAddress?.country??null,source:"GLEIF_LEI"}};
}
Deno.serve(async(req)=>{
 if(req.method!=="POST")return json({error:"method_not_allowed"},405);
 const auth=req.headers.get("authorization")??"";
 if(!auth.toLowerCase().startsWith("bearer "))return json({error:"authentication_required"},401);
 const token=auth.slice(7).trim(); const {data:userData,error:userError}=await admin.auth.getUser(token);
 if(userError||!userData.user)return json({error:"authentication_required"},401);
 const userId=userData.user.id;
 let body:Record<string,unknown>; try{body=await req.json()}catch{return json({error:"invalid_json"},400);}
 const name=String(body.name??"").trim(),email=String(body.email??"").trim().toLowerCase(),phone=String(body.phone??"").trim();
 const kind=body.subject_kind?String(body.subject_kind):null,country=body.country?String(body.country).trim().toUpperCase():null,lei=body.lei?String(body.lei).trim().toUpperCase():null;
 if(!name||name.length>240)return json({error:"invalid_name"},400);
 if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)||email.length>320)return json({error:"invalid_email"},400);
 if(!/^\+?[0-9\s().-]{7,32}$/.test(phone))return json({error:"invalid_phone"},400);

 const {data:existing}=await admin.from("giril_onboarding_cases").select("id").eq("applicant_user_id",userId).not("state","in","(ADMITTED,REJECTED)").maybeSingle();
 let caseId=existing?.id;
 if(caseId){
  const {error}=await admin.from("giril_onboarding_cases").update({requested_name:name,email,phone,subject_kind:kind,country_iso2:country,state:lei?"VERIFYING":"COLLECTING",updated_at:new Date().toISOString()}).eq("id",caseId).eq("applicant_user_id",userId);
  if(error)return json({error:"case_update_failed"},500);
 }else{
  const {data,error}=await admin.from("giril_onboarding_cases").insert({applicant_user_id:userId,requested_name:name,email,phone,subject_kind:kind,country_iso2:country,state:lei?"VERIFYING":"COLLECTING"}).select("id").single();
  if(error)return json({error:"case_create_failed",detail:error.message},500); caseId=data.id;
 }

 let verification:any=null,trust:any=null;
 if(lei){
  const result=await gleif(lei);
  const source=await admin.from("giril_ref_sources").select("id").eq("source_key","GLEIF_LEI").maybeSingle();
  if(!source.data?.id)return json({error:"gleif_source_not_registered"},500);
  const targetHash=await sha256(lei), now=new Date().toISOString();
  const {data:check,error:checkError}=await admin.from("giril_verification_checks").insert({onboarding_case_id:caseId,check_type:"COMPANY_REGISTRY",target_hash:targetHash,source_id:source.data.id,status:result.status,verifier_version:"giril-gleif-v1",verification_method:"GLEIF_LEI_API",completed_at:now,metadata:result.payload??{reason:result.status}}).select("id,status").single();
  if(checkError)return json({error:"verification_record_failed",detail:checkError.message},500);
  verification=check;

  const subject=await admin.rpc("trust_register_subject",{p_tenant_id:null,p_subject_kind:"GIRIL_APPLICANT",p_external_ref:`giril:${caseId}`,p_display_name:name,p_identity_document:{applicant_user_id:userId,case_id:caseId}});
  if(subject.error||!subject.data)return json({error:"trust_subject_failed",detail:subject.error?.message},500);
  const subjectId=subject.data.id;
  const contentHash=await sha256(JSON.stringify(result.payload??{reason:result.status}));
  const evidence=await admin.rpc("trust_record_evidence",{p_subject_id:subjectId,p_evidence_type:"GIRIL_COMPANY_REGISTRY",p_source_type:"AUTHORITATIVE_REGISTRY",p_source_id:"GLEIF_LEI",p_content_type:"application/json",p_content_uri:null,p_content_hash:contentHash,p_collected_at:now,p_expires_at:null,p_metadata:{onboarding_case_id:caseId,verification_check_id:check.id,claim_target_hash:targetHash}});
  if(evidence.error||!evidence.data)return json({error:"trust_evidence_failed",detail:evidence.error?.message},500);
  const evidenceId=evidence.data.id;
  const verifiedHash=await sha256(JSON.stringify({evidence_id:evidenceId,content_hash:contentHash,status:result.status,source:"GLEIF_LEI",verifier_version:"giril-gleif-v1"}));
  const evStatus=result.status==="VERIFIED"?"VERIFIED":"FAILED";
  const ev=await admin.rpc("trust_commit_evidence_verification",{p_evidence_id:evidenceId,p_verification_status:evStatus,p_verifier_type:"GIRIL",p_verifier_id:"GLEIF_LEI",p_verifier_version:"giril-gleif-v1",p_verification_method:"GLEIF_LEI_API",p_signer_key_id:null,p_signature_algorithm:null,p_verified_payload_hash:contentHash,p_verified_at:now,p_reason:result.status==="VERIFIED"?"authoritative_active_lei":"authoritative_source_did_not_verify_lei"});
  if(ev.error)return json({error:"trust_evidence_verification_failed",detail:ev.error.message},500);
  const state=await admin.rpc("trust_compute_state",{p_subject_id:subjectId});
  if(state.error)return json({error:"trust_state_failed",detail:state.error.message},500);
  trust={subject_id:subjectId,state:state.data?.state??null,assurance_level:state.data?.assurance_level??null,evidence_id:evidenceId};
  await admin.from("giril_onboarding_cases").update({state:result.status==="VERIFIED"?"CONTROL_REVIEW":"MANUAL_REVIEW",updated_at:now}).eq("id",caseId);
 }
 if(verification?.status==="VERIFIED"){const admission=await admin.rpc("giril_control_admit",{p_onboarding_case_id:caseId});if(admission.error)return json({error:"control_admission_failed",detail:admission.error.message},500);return json({status:"admitted",onboarding_case_id:caseId,verification,trust,admission_id:admission.data});}\n return json({status:"accepted",onboarding_case_id:caseId,verification,trust,admission:"CONTROL_REVIEW"});
});