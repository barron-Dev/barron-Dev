import type { MdiCapability, ProviderAdapter } from './registry';
interface CamaraConfig{baseUrl:string;clientId:string;clientSecret:string;mode:'2lo'|'3lo';tokenUrl:string;countries:string[];}
export class CamaraAdapter implements ProviderAdapter{
  slug='camara';capabilities:MdiCapability[]=['number_verify','sim_swap','device_reachability','device_identity','location_verify','location_retrieve','roaming','kyc_match','line_type','carrier_lookup'];
  constructor(private cfg:CamaraConfig){} get countries(){return this.cfg.countries.length?this.cfg.countries:['*'];}
  private cache?:{token:string;exp:number};
  private async token(userToken?:string){if(this.cfg.mode==='3lo'){if(!userToken)throw new Error('camara_3lo_user_token_required');return userToken;}if(this.cache&&this.cache.exp>Date.now()+30000)return this.cache.token;const r=await fetch(this.cfg.tokenUrl,{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'client_credentials',client_id:this.cfg.clientId,client_secret:this.cfg.clientSecret})});if(!r.ok)throw new Error('camara_token_'+r.status);const j=await r.json() as any;if(!j.access_token)throw new Error('camara_token_missing');this.cache={token:j.access_token,exp:Date.now()+(j.expires_in??3600)*1000};return j.access_token;}
  private async post<T>(path:string,body:unknown,userToken?:string){const r=await fetch(this.cfg.baseUrl.replace(/\/$/,'')+path,{method:'POST',headers:{authorization:'Bearer '+await this.token(userToken),'content-type':'application/json'},body:JSON.stringify(body)});if(!r.ok)throw new Error('camara_'+r.status+':'+(await r.text().catch(()=>'' )).slice(0,200));return await r.json() as T;}
  async invoke<T>(cap:MdiCapability,params:Record<string,unknown>):Promise<T>{const ut=params.userToken as string|undefined,phone=params.phoneNumber as string;switch(cap){
    case 'number_verify':{const r=await this.post<any>('/number-verification/v0/verify',{phoneNumber:phone},ut);return {verified:!!r.devicePhoneNumberVerified,confidence:r.devicePhoneNumberVerified?.98:.55,raw:r} as T;}
    case 'sim_swap':{const r=await this.post<any>('/sim-swap/v0/check',{phoneNumber:phone,maxAge:params.maxAgeHours??240},ut);return {swapped:!!r.swapped,lastSwapAt:r.latestSimChange??null,confidence:.92,raw:r} as T;}
    case 'device_reachability':{const r=await this.post<any>('/device-status/v0/connectivity',{device:{phoneNumber:phone}},ut);return {reachable:r.connectivityStatus==='CONNECTED_DATA'||r.connectivityStatus==='CONNECTED_SMS',status:r.connectivityStatus,confidence:.85,raw:r} as T;}
    case 'device_identity':{const r=await this.post<any>('/device-identifier/v0/retrieve',{device:{phoneNumber:phone}},ut);return {imei:(r.imei??[]).map((x:any)=>x.imei),confidence:.9,raw:r} as T;}
    case 'location_verify':{const r=await this.post<any>('/location-verification/v0/verify',{device:{phoneNumber:phone},area:{areaType:'Circle',center:{latitude:params.lat,longitude:params.lon},radius:params.radiusM??1000},maxAge:params.maxAgeS??300},ut);return {match:r.verificationResult==='TRUE',confidence:.88,raw:r} as T;}
    case 'location_retrieve':{const r=await this.post<any>('/location-retrieval/v0/retrieve',{device:{phoneNumber:phone},maxAge:params.maxAgeS??60},ut);return {lat:r.area?.center?.latitude,lon:r.area?.center?.longitude,radiusM:r.area?.radius,at:r.lastLocationTime,confidence:.85,raw:r} as T;}
    case 'roaming':{const r=await this.post<any>('/roaming-status/v0/roaming',{device:{phoneNumber:phone}},ut);return {roaming:r.roaming===true,countryCode:r.countryCode??null,confidence:.9,raw:r} as T;}
    case 'kyc_match':{const r=await this.post<any>('/kyc-match/v0/match',{phoneNumber:phone,idDocument:params.idDocument,name:params.name,givenName:params.givenName,familyName:params.familyName,birthdate:params.birthdate},ut);return {match:r.kycMatchResult==='true',confidence:.9,raw:r} as T;}
    default:throw new Error('camara_unsupported:'+cap);
  }}
}
