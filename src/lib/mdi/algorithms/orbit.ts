const MU = 398600.4418;
const RE = 6378.137;
const J2 = 1.08262668e-3;
const DEG = Math.PI / 180;
const TWO_PI = Math.PI * 2;

export interface Tle {
  noradId: number; name: string; epoch: Date;
  inclination: number; raan: number; eccentricity: number;
  argPerigee: number; meanAnomaly: number; meanMotion: number;
  bstar: number; revNumber: number;
}
export interface Vec3 { x:number; y:number; z:number; }

export function parseTle(name:string,l1:string,l2:string):Tle {
  const yy=parseInt(l1.slice(18,20),10), day=parseFloat(l1.slice(20,32));
  const year=yy<57?2000+yy:1900+yy;
  const epoch=new Date(Date.UTC(year,0,1));
  epoch.setUTCDate(epoch.getUTCDate()+Math.floor(day)-1);
  epoch.setUTCMilliseconds((day-Math.floor(day))*86400000);
  return {
    noradId:parseInt(l1.slice(2,7),10), name:name.trim(), epoch,
    inclination:parseFloat(l2.slice(8,16))*DEG, raan:parseFloat(l2.slice(17,25))*DEG,
    eccentricity:parseFloat('0.'+l2.slice(26,33).trim()),
    argPerigee:parseFloat(l2.slice(34,42))*DEG, meanAnomaly:parseFloat(l2.slice(43,51))*DEG,
    meanMotion:parseFloat(l2.slice(52,63))*TWO_PI/86400,
    bstar:parseFloat(l1.slice(53,61))||0, revNumber:parseInt(l2.slice(63,68),10)||0,
  };
}
const sub=(a:Vec3,b:Vec3):Vec3=>({x:a.x-b.x,y:a.y-b.y,z:a.z-b.z});
function j2Rates(t:Tle){
  const n=t.meanMotion,a=Math.cbrt(MU/(n*n)),e=t.eccentricity,i=t.inclination,p=a*(1-e*e);
  const f=J2*Math.pow(RE/p,2);
  return {a,raanDot:-1.5*n*f*Math.cos(i),argpDot:0.75*n*f*(5*Math.cos(i)**2-1),
    mDot:n*(1+0.75*f*Math.sqrt(1-e*e)*(3*Math.cos(i)**2-1))};
}
function kepler(M:number,e:number){
  let E=e<0.8?M:Math.PI;
  for(let i=0;i<60;i++){const d=(E-e*Math.sin(E)-M)/(1-e*Math.cos(E));E-=d;if(Math.abs(d)<1e-10)break;}
  return E;
}
export function gmst(date:Date){
  const jd=date.getTime()/86400000+2440587.5,T=(jd-2451545)/36525;
  let g=280.46061837+360.98564736629*(jd-2451545)+0.000387933*T*T-(T*T*T)/38710000;
  g=((g%360)+360)%360; return g*DEG;
}
export function propagateEci(t:Tle,at:Date):{r:Vec3;v:Vec3}{
  const dt=(at.getTime()-t.epoch.getTime())/1000,{a,raanDot,argpDot,mDot}=j2Rates(t);
  const raan=t.raan+raanDot*dt,argp=t.argPerigee+argpDot*dt;
  const M=((t.meanAnomaly+mDot*dt)%TWO_PI+TWO_PI)%TWO_PI,e=t.eccentricity,E=kepler(M,e);
  const xp=a*(Math.cos(E)-e),yp=a*Math.sqrt(1-e*e)*Math.sin(E),rr=a*(1-e*Math.cos(E));
  const n=Math.sqrt(MU/(a*a*a));
  const vxp=(-a*n*Math.sin(E))/(1-e*Math.cos(E));
  const vyp=(a*n*Math.sqrt(1-e*e)*Math.cos(E))/(1-e*Math.cos(E));
  const cO=Math.cos(raan),sO=Math.sin(raan),ci=Math.cos(t.inclination),si=Math.sin(t.inclination),cw=Math.cos(argp),sw=Math.sin(argp);
  const R11=cO*cw-sO*sw*ci,R12=-cO*sw-sO*cw*ci,R21=sO*cw+cO*sw*ci,R22=-sO*sw+cO*cw*ci,R31=sw*si,R32=cw*si;
  return {r:{x:R11*xp+R12*yp,y:R21*xp+R22*yp,z:R31*xp+R32*yp},
    v:{x:R11*vxp+R12*vyp,y:R21*vxp+R22*vyp,z:R31*vxp+R32*vyp}};
}
export function eciToEcef(r:Vec3,at:Date):Vec3{const g=gmst(at),c=Math.cos(g),s=Math.sin(g);return{x:r.x*c+r.y*s,y:-r.x*s+r.y*c,z:r.z};}
export function ecefToGeodetic(p:Vec3){
  const a=6378.137,f=1/298.257223563,e2=f*(2-f),lon=Math.atan2(p.y,p.x),rr=Math.hypot(p.x,p.y);
  let lat=Math.atan2(p.z,rr*(1-e2)),alt=0,N=a;
  for(let i=0;i<5;i++){const sl=Math.sin(lat);N=a/Math.sqrt(1-e2*sl*sl);alt=rr/Math.cos(lat)-N;lat=Math.atan2(p.z,rr*(1-e2*N/(N+alt)));}
  return{lat:lat/DEG,lon:lon/DEG,altKm:alt};
}
export function geodeticToEcef(lat:number,lon:number,altKm=0):Vec3{
  const a=6378.137,f=1/298.257223563,e2=f*(2-f),p=lat*DEG,l=lon*DEG,N=a/Math.sqrt(1-e2*Math.sin(p)**2);
  return{x:(N+altKm)*Math.cos(p)*Math.cos(l),y:(N+altKm)*Math.cos(p)*Math.sin(l),z:(N*(1-e2)+altKm)*Math.sin(p)};
}
export interface LookAngle{azimuth:number;elevation:number;rangeKm:number;}
export function lookAngles(sat:Vec3,obsLat:number,obsLon:number,obsAltKm=0):LookAngle{
  const o=geodeticToEcef(obsLat,obsLon,obsAltKm),d=sub(sat,o),p=obsLat*DEG,l=obsLon*DEG;
  const east=-Math.sin(l)*d.x+Math.cos(l)*d.y;
  const north=-Math.sin(p)*Math.cos(l)*d.x-Math.sin(p)*Math.sin(l)*d.y+Math.cos(p)*d.z;
  const up=Math.cos(p)*Math.cos(l)*d.x+Math.cos(p)*Math.sin(l)*d.y+Math.sin(p)*d.z;
  const range=Math.hypot(east,north,up),el=Math.asin(up/range)/DEG;
  let az=Math.atan2(east,north)/DEG;if(az<0)az+=360;
  return{azimuth:az,elevation:el,rangeKm:range};
}
export interface Pass{aos:Date;los:Date;tca:Date;maxElevation:number;minRangeKm:number;startAzimuth:number;endAzimuth:number;}
export function predictPasses(t:Tle,obs:{lat:number;lon:number;altKm?:number},from:Date,hours=72,minElevation=5,stepS=20):Pass[]{
  const out:Pass[]=[],end=from.getTime()+hours*3600000;
  const look=(ms:number)=>lookAngles(eciToEcef(propagateEci(t,new Date(ms)).r,new Date(ms)),obs.lat,obs.lon,obs.altKm??0);
  const bisect=(t0:number,t1:number,target:number)=>{let a=t0,b=t1;for(let i=0;i<40;i++){const m=(a+b)/2;if((look(a).elevation-target)*(look(m).elevation-target)<=0)b=m;else a=m;}return(a+b)/2;};
  let prevT=from.getTime(),prev=look(prevT),inPass=prev.elevation>=minElevation,start=inPass?prevT:0;
  let peak={el:prev.elevation,t:prevT,la:prev};
  for(let tms=prevT+stepS*1000;tms<=end;tms+=stepS*1000){
    const cur=look(tms),inside=cur.elevation>=minElevation;
    if(!inPass&&inside){start=bisect(prevT,tms,minElevation);peak={el:cur.elevation,t:tms,la:cur};inPass=true;}
    else if(inPass&&inside&&cur.elevation>peak.el)peak={el:cur.elevation,t:tms,la:cur};
    else if(inPass&&!inside){const los=bisect(prevT,tms,minElevation);out.push({aos:new Date(start),los:new Date(los),tca:new Date(peak.t),maxElevation:+peak.el.toFixed(3),minRangeKm:+peak.la.rangeKm.toFixed(3),startAzimuth:+look(start).azimuth.toFixed(2),endAzimuth:+look(los).azimuth.toFixed(2)});inPass=false;}
    prevT=tms;prev=cur;
  }
  return out;
}
export function footprintRadiusKm(altKm:number,minElevationDeg=0){
  const e=minElevationDeg*DEG,eta=Math.asin((RE/(RE+altKm))*Math.cos(e));return RE*(Math.PI/2-e-eta);
}
export function haversineKm(lat1:number,lon1:number,lat2:number,lon2:number){
  const R=6371.0088,dLat=(lat2-lat1)*DEG,dLon=(lon2-lon1)*DEG;
  const a=Math.sin(dLat/2)**2+Math.cos(lat1*DEG)*Math.cos(lat2*DEG)*Math.sin(dLon/2)**2;
  return 2*R*Math.asin(Math.sqrt(a));
}
export function groundFootprint(t:Tle,at:Date,minEl=0){const geo=ecefToGeodetic(eciToEcef(propagateEci(t,at).r,at));return{...geo,radiusKm:footprintRadiusKm(geo.altKm,minEl)};}
export function footprintCovers(t:Tle,at:Date,lat:number,lon:number,minEl=0){const fp=groundFootprint(t,at,minEl);return haversineKm(fp.lat,fp.lon,lat,lon)<=fp.radiusKm;}
export function imagingOpportunities(tles:Tle[],lat:number,lon:number,from:Date,hours=48,minEl=20){
  const out:Array<{noradId:number;name:string;pass:Pass}>=[];for(const t of tles)for(const pass of predictPasses(t,{lat,lon},from,hours,minEl,30))out.push({noradId:t.noradId,name:t.name,pass});
  return out.sort((a,b)=>a.pass.aos.getTime()-b.pass.aos.getTime());
}
