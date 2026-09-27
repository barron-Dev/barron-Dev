import type { SupabaseClient } from '@supabase/supabase-js';
import { CamaraAdapter } from '../providers/camara';
import { CelesTrakAdapter, SentinelHubAdapter } from '../providers/satellite';
import { TwilioLookupAdapter, NumverifyAdapter, InternalGraphAdapter } from '../providers/aggregators';
import type { ProviderAdapter } from '../providers/registry';
export interface MdiRuntime{sb:SupabaseClient;registry:ProviderAdapter[];health:Record<string,{id?:string;status:string;weight:number;cost:number}>}
export async function bootstrapMdi(sb:SupabaseClient):Promise<MdiRuntime>{
 const registry:ProviderAdapter[]=[];
 if(process.env.CAMARA_BASE_URL&&process.env.CAMARA_CLIENT_ID&&process.env.CAMARA_CLIENT_SECRET&&process.env.CAMARA_TOKEN_URL)registry.push(new CamaraAdapter({baseUrl:process.env.CAMARA_BASE_URL,tokenUrl:process.env.CAMARA_TOKEN_URL,clientId:process.env.CAMARA_CLIENT_ID,clientSecret:process.env.CAMARA_CLIENT_SECRET,mode:process.env.CAMARA_MODE==='3lo'?'3lo':'2lo',countries:(process.env.CAMARA_COUNTRIES??'').split(',').map(x=>x.trim().toUpperCase()).filter(Boolean)}));
 if(process.env.TWILIO_ACCOUNT_SID&&process.env.TWILIO_AUTH_TOKEN)registry.push(new TwilioLookupAdapter({accountSid:process.env.TWILIO_ACCOUNT_SID,authToken:process.env.TWILIO_AUTH_TOKEN,region:process.env.TWILIO_LOOKUP_REGION}));
 if(process.env.NUMVERIFY_KEY)registry.push(new NumverifyAdapter(process.env.NUMVERIFY_KEY));
 registry.push(new InternalGraphAdapter(sb));
 if(process.env.CELESTRAK_ENABLED==='true')registry.push(new CelesTrakAdapter());
 if(process.env.SENTINEL_HUB_CLIENT_ID&&process.env.SENTINEL_HUB_CLIENT_SECRET&&process.env.SENTINEL_HUB_BASE_URL)registry.push(new SentinelHubAdapter({baseUrl:process.env.SENTINEL_HUB_BASE_URL,clientId:process.env.SENTINEL_HUB_CLIENT_ID,clientSecret:process.env.SENTINEL_HUB_CLIENT_SECRET}));
 const {data,error}=await sb.from('mdi_providers').select('id,slug,status,weight,cost_micros');if(error)throw error;
 const health:MdiRuntime['health']={};for(const p of data??[])health[p.slug]={id:p.id,status:p.status,weight:Number(p.weight),cost:Number(p.cost_micros)/1e6};
 return {sb,registry,health};
}
