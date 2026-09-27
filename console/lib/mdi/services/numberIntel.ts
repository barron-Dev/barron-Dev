import type { SupabaseClient } from '@supabase/supabase-js';
import { normalizeMsisdn } from '../algorithms/msisdn';
import { fuseRisk, type RiskSignal } from '../algorithms/risk';
import { invokeWithFallback, type ProviderAdapter } from '../providers/registry';
export interface NumberIntelInput{raw:string;defaultCountryIso2?:string;caseId?:string;actorId?:string;lawfulBasis?:string;depth?:'basic'|'standard'|'deep'}
export async function resolveNumber(sb:SupabaseClient,registry:ProviderAdapter[],health:Record<string,any>,input:NumberIntelInput){
 const parsed=normalizeMsisdn(input.raw,input.defaultCountryIso2);if(!parsed)return {ok:false as const,error:'unparseable_number',raw:input.raw};
 const {data:subjectId,error:upErr}=await sb.rpc('mdi_upsert_subject',{p_kind:'msisdn',p_canonical:parsed.e164,p_display:parsed.e164,p_country:parsed.countryIso2??null,p_attrs:{callingCode:parsed.callingCode,source:'resolveNumber'},p_pii:2});if(upErr)throw upErr;
 const ctx={subjectId,caseId:input.caseId,actorId:input.actorId,capability:'carrier_lookup' as const};const signals:RiskSignal[]=[];
 const carrier=await invokeWithFallback<any>(sb,registry,'carrier_lookup',{phoneNumber:parsed.e164},ctx,health,parsed.countryIso2);
 if(carrier){await sb.from('mdi_number_intel').upsert({subject_id:subjectId,e164:parsed.e164,country_iso2:parsed.countryIso2??null,calling_code:parsed.callingCode,national_number:parsed.nationalNumber,line_type:carrier.data.lineType??'unknown',is_valid:carrier.data.valid??true,is_portable:carrier.data.portable??null,ported_at:carrier.data.portedAt??null,carrier_name:carrier.data.carrier??null,mcc:carrier.data.mcc??null,mnc:carrier.data.mnc??null,roaming:carrier.data.roaming??null,reachable:carrier.data.reachable??null,raw:carrier.data.raw??carrier.data,updated_at:new Date().toISOString()},{onConflict:'subject_id'});if(carrier.data.lineType==='voip')signals.push({k:'voip_line',lr:3.5,w:.8,conf:.85});if(carrier.data.recentlyPorted)signals.push({k:'recent_port',lr:2.4,w:.7,conf:.8});}
 if(input.depth!=='basic'&&input.lawfulBasis){const swap=await invokeWithFallback<any>(sb,registry,'sim_swap',{phoneNumber:parsed.e164,maxAgeHours:720},{...ctx,capability:'sim_swap'},health,parsed.countryIso2);if(swap?.data?.swapped){const ageS=swap.data.lastSwapAt?(Date.now()-new Date(swap.data.lastSwapAt).getTime())/1000:0;await sb.from('mdi_carrier_events').insert({subject_id:subjectId,event_type:'sim_swap',occurred_at:swap.data.lastSwapAt??new Date().toISOString(),confidence:swap.data.confidence??.8,source:'carrier_api',provider_id:health[swap.provider]?.id??null,raw:swap.data.raw??{}});signals.push({k:'sim_swap',lr:22,w:1,conf:swap.data.confidence??.9,ageS,halfLifeS:604800});}}
 if(input.depth==='deep'){const rep=await invokeWithFallback<any>(sb,registry,'number_reputation',{phoneNumber:parsed.e164,subjectId},{...ctx,capability:'number_reputation'},health,parsed.countryIso2);if(rep?.data){const complaints=rep.data.complaints??0;if(complaints>0)signals.push({k:'osint_complaints',lr:1+Math.log1p(complaints)*.8,w:.9,conf:Math.min(.4+complaints*.05,.9)});}}
 const {count:localReports}=await sb.from('mdi_caller_reports').select('*',{count:'exact',head:true}).eq('subject_id',subjectId).gte('occurred_at',new Date(Date.now()-180*86400_000).toISOString());
 if((localReports??0)>0)signals.push({k:'internal_complaints',lr:1+Math.log1p(localReports??0)*1.2,w:1,conf:Math.min(.6+(localReports??0)*.04,.95)});
 const risk=fuseRisk(.02,signals);await sb.rpc('mdi_refresh_risk',{p_subject:subjectId});
 return {ok:true as const,subjectId,e164:parsed.e164,countryIso2:parsed.countryIso2,risk,providers:{carrier:carrier?.provider??null},signals};
}
export async function resolveDevice(sb:SupabaseClient,rawImei:string,input:{caseId?:string;actorId?:string}={}){
 const imei=rawImei.replace(/[^0-9]/g,'');if(imei.length!==15)return {ok:false as const,error:'invalid_imei_length'};const tac=imei.slice(0,8);
 const {data:subjectId,error}=await sb.rpc('mdi_upsert_subject',{p_kind:'imei',p_canonical:imei,p_display:imei,p_attrs:{tac},p_pii:2});if(error)throw error;
 const {data:tacRow}=await sb.from('mdi_imei_tac').select('*').eq('tac',tac).maybeSingle();
 await sb.from('mdi_device_intel').upsert({subject_id:subjectId,imei,tac,brand:tacRow?.brand??null,model:tacRow?.model??null,device_type:tacRow?.device_type??null,last_seen:new Date().toISOString(),updated_at:new Date().toISOString()},{onConflict:'subject_id'});
 await sb.rpc('mdi_refresh_risk',{p_subject:subjectId});return {ok:true as const,subjectId,imei,tac,device:tacRow??null};
}
