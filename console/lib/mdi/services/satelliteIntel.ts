import type { SupabaseClient } from '@supabase/supabase-js';
import { parseTle,predictPasses,footprintCovers,type Tle } from '../algorithms/orbit';
export async function syncCatalog(sb:SupabaseClient,fetchTles:(group:string)=>Promise<Tle[]>,groups=['active','weather','noaa','science','geo']){
 const seen=new Map<number,Tle>();for(const g of groups){try{for(const t of await fetchTles(g))seen.set(t.noradId,t)}catch{}}
 const rows=[...seen.values()].map(t=>({norad_id:t.noradId,name:t.name,tle_line1:t.line1,tle_line2:t.line2,epoch:t.epoch.toISOString(),inclination:+(t.inclination*180/Math.PI).toFixed(4),raan:+(t.raan*180/Math.PI).toFixed(4),eccentricity:t.eccentricity,argp:+(t.argPerigee*180/Math.PI).toFixed(4),mean_anomaly:+(t.meanAnomaly*180/Math.PI).toFixed(4),mean_motion:+(t.meanMotion*86400/(2*Math.PI)).toFixed(8),bstar:t.bstar,updated_at:new Date().toISOString()}));
 for(let i=0;i<rows.length;i+=500){const {error}=await sb.from('mdi_satellites').upsert(rows.slice(i,i+500),{onConflict:'norad_id'});if(error)throw error}return {synced:rows.length};
}
export async function computePasses(sb:SupabaseClient,noradIds:number[],observer:{lat:number;lon:number;altKm?:number},hours=72,minElevation=5){
 const {data:sats,error}=await sb.from('mdi_satellites').select('norad_id,name,tle_line1,tle_line2').in('norad_id',noradIds);if(error)throw error;const out:any[]=[];
 for(const s of sats??[]){if(!s.tle_line1||!s.tle_line2)continue;const tle=parseTle(s.name,s.tle_line1,s.tle_line2);for(const p of predictPasses(tle,observer,new Date(),hours,minElevation))out.push({norad_id:s.norad_id,observer_lat:observer.lat,observer_lon:observer.lon,observer_alt_m:Math.round((observer.altKm??0)*1000),aos:p.aos.toISOString(),los:p.los.toISOString(),tca:p.tca.toISOString(),max_elevation:p.maxElevation,min_range_km:p.minRangeKm,start_azimuth:p.startAzimuth,end_azimuth:p.endAzimuth})}
 for(let i=0;i<out.length;i+=500){const {error}=await sb.from('mdi_satellite_passes').insert(out.slice(i,i+500));if(error)throw error}return out;
}
export async function overflightAttribution(sb:SupabaseClient,lat:number,lon:number,from:Date,to:Date,minElevation=10){
 const {data:sats,error}=await sb.from('mdi_satellites').select('norad_id,name,purpose,is_imaging,tle_line1,tle_line2').not('tle_line1','is',null);if(error)throw error;const hits:any[]=[];const hrs=(to.getTime()-from.getTime())/3600000;
 for(const s of sats??[]){if(!s.tle_line1||!s.tle_line2)continue;const tle=parseTle(s.name,s.tle_line1,s.tle_line2);for(const p of predictPasses(tle,{lat,lon},from,hrs,minElevation,2)){if(p.aos>=from&&p.los<=to)hits.push({noradId:s.norad_id,name:s.name,purpose:s.purpose,imaging:s.is_imaging,aos:p.aos,tca:p.tca,los:p.los,maxElevation:p.maxElevation})}}
 return hits.sort((a,b)=>a.aos.getTime()-b.aos.getTime());
}
export async function correlateLocationWithSpace(sb:SupabaseClient,subjectId:string,windowHours=24){
 const since=new Date(Date.now()-windowHours*3600000).toISOString();const {data:locs}=await sb.from('mdi_location_signals').select('id,lat,lon,observed_at,confidence').eq('subject_id',subjectId).gte('observed_at',since).not('lat','is',null);const {data:sats}=await sb.from('mdi_satellites').select('norad_id,name,purpose,tle_line1,tle_line2').not('tle_line1','is',null);const out:any[]=[];
 for(const loc of locs??[])for(const s of sats??[]){if(!s.tle_line1||!s.tle_line2)continue;const tle=parseTle(s.name,s.tle_line1,s.tle_line2),t=new Date(loc.observed_at);if(footprintCovers(tle,t,loc.lat,loc.lon,0))out.push({subjectId,locationSignalId:loc.id,noradId:s.norad_id,name:s.name,purpose:s.purpose,at:loc.observed_at,strength:s.purpose==='imaging'?.7:.4})}
 return out;
}
