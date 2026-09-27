import type { SupabaseClient } from '@supabase/supabase-js';

export type MdiCapability =
  | 'number_verify' | 'carrier_lookup' | 'line_type' | 'sim_swap' | 'port_history'
  | 'device_reachability' | 'device_identity' | 'location_verify' | 'location_retrieve'
  | 'roaming' | 'kyc_match' | 'sms_deliverability' | 'tac_lookup' | 'number_reputation'
  | 'tle_catalog' | 'orbit_propagate' | 'imagery' | 'gnss_interference' | 'sat_comms';

export interface ProviderCallCtx { capability:MdiCapability; subjectId?:string; caseId?:string; actorId?:string; correlationId?:string; }
export interface ProviderAdapter { slug:string; capabilities:MdiCapability[]; countries:string[]|['*']; invoke<T=unknown>(capability:MdiCapability,params:Record<string,unknown>,ctx:ProviderCallCtx):Promise<T>; }
type Health={id?:string;status:string;weight:number;cost:number};

export function selectProviders(registry:ProviderAdapter[],capability:MdiCapability,countryIso2:string|undefined,health:Record<string,Health>):ProviderAdapter[]{
  return registry.filter(p=>p.capabilities.includes(capability)).filter(p=>!countryIso2||p.countries[0]==='*'||p.countries.includes(countryIso2)).sort((a,b)=>{
    const ha=health[a.slug]??{status:'active',weight:1,cost:0},hb=health[b.slug]??{status:'active',weight:1,cost:0};
    return ((hb.status==='active'?1:0)*hb.weight/(1+hb.cost))-((ha.status==='active'?1:0)*ha.weight/(1+ha.cost));
  });
}
export async function invokeWithFallback<T>(sb:SupabaseClient,registry:ProviderAdapter[],capability:MdiCapability,params:Record<string,unknown>,ctx:ProviderCallCtx,health:Record<string,Health>,countryIso2?:string,opts:{timeoutMs?:number;minConfidence?:number}={}):Promise<{data:T;provider:string}|null>{
  for(const p of selectProviders(registry,capability,countryIso2,health)){
    const t0=Date.now(),requestHash=await sha256Hex(JSON.stringify({p:p.slug,capability,params}));
    try{
      const data=await Promise.race([p.invoke<T>(capability,params,ctx),new Promise<never>((_,rej)=>setTimeout(()=>rej(new Error('provider_timeout')),opts.timeoutMs??8000))]);
      const conf=Number((data as {confidence?:number})?.confidence??1),ok=conf>=(opts.minConfidence??0);
      await sb.from('mdi_provider_calls').insert({capability,subject_id:ctx.subjectId??null,case_id:ctx.caseId??null,actor_id:ctx.actorId??null,request_hash:requestHash,ok,latency_ms:Date.now()-t0,cost_micros:Math.round((health[p.slug]?.cost??0)*1e6),provider_id:health[p.slug]?.id??null});
      if(ok)return {data,provider:p.slug};
    }catch(err){
      await sb.from('mdi_provider_calls').insert({capability,subject_id:ctx.subjectId??null,case_id:ctx.caseId??null,actor_id:ctx.actorId??null,request_hash:requestHash,ok:false,latency_ms:Date.now()-t0,error_code:String(err instanceof Error?err.message:err).slice(0,120),provider_id:health[p.slug]?.id??null});
    }
  } return null;
}
async function sha256Hex(s:string){const b=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s));return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');}
