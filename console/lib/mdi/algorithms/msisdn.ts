export interface ParsedMsisdn{e164:string;countryIso2?:string;callingCode:string;nationalNumber:string}
const CC:Record<string,string>={AE:'971',SA:'966',QA:'974',KW:'965',BH:'973',OM:'968',JO:'962',EG:'20',NG:'234',GB:'44',US:'1'};
export function normalizeMsisdn(raw:string,defaultCountryIso2?:string):ParsedMsisdn|null{
 let v=raw.trim().replace(/[().\-\s]/g,''); if(v.startsWith('00'))v='+'+v.slice(2);
 let digits=v.replace(/\D/g,''); if(!digits)return null;
 if(!v.startsWith('+')){const cc=CC[(defaultCountryIso2??'').toUpperCase()];if(!cc)return null;digits=cc+digits;}
 if(digits.length<7||digits.length>15)return null;
 const cc=Object.values(CC).sort((a,b)=>b.length-a.length).find(x=>digits.startsWith(x)); if(!cc)return null;
 const e164='+'+digits; return {e164,countryIso2:Object.entries(CC).find(([,x])=>x===cc)?.[0],callingCode:cc,nationalNumber:digits.slice(cc.length)};
}
