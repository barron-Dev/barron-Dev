const MU=398600.4418,RE=6378.137,J2=1.08262668e-3,OMEGA_E=7.2921159e-5,DEG=Math.PI/180,TWO_PI=Math.PI*2;

export interface Tle{
  noradId:number;name:string;epoch:Date;inclination:number;raan:number;eccentricity:number;
  argPerigee:number;meanAnomaly:number;meanMotion:number;bstar:number;revNumber:number;
}
export function parseTle(name:string,l1:string,l2:string):Tle{
  const epochYear=parseInt(l1.slice(18,20),10),epochDay=parseFloat(l1.slice(20,32));
  const year=epochYear<57?2000+epochYear:1900+epochYear,epoch=new Date(Date.UTC(year,0,1));
  epoch.setUTCDate(epoch.getUTCDate()+Math.floor(epochDay)-1);
  epoch.setUTCMilliseconds((epochDay-Math.floor(epochDay))*86400000);
  return {noradId:parseInt(l1.slice(2,7),10),name:name.trim(),epoch,
    inclination:parseFloat(l2.slice(8,16))*DEG,raan:parseFloat(l2.slice(17,25))*DEG,
    eccentricity:parseFloat('0.'+l2.slice(26,33).trim()),argPerigee:parseFloat(l2.slice(34,42))*DEG,
    meanAnomaly:parseFloat(l2.slice(43,51))*DEG,meanMotion:parseFloat(l2.slice(52,63))*TWO_PI/86400,
    bstar:parseFloat(l1.slice(53,61))||0,revNumber:parseInt(l2.slice(63,68),10)||0};
}
export interface Vec3{x:number;y:number;z:number}
const sub=(a:Vec3,b:Vec3):Vec3=>({x:a.x-b.x,y:a.y-b.y,z:a.z-b.z});
function j2Rates(tle:Tle){
  const n=tle.meanMotion,a=Math.cbrt(MU/(n*n)),e=tle.eccentricity,i=tle.inclination,p=a*(1-e*e),f=J2*Math.pow(RE/p,2);
  return {a,raanDot:-1.5*n*f*Math.cos(i),argpDot:.75*n*f*(5*Math.cos(i)**2-1),
    mDot:n*(1+.75*f*Math.sqrt(1-e*e)*(3*Math.cos(i)**2-1))};
}
function kepler(M:number,e:number,tol=1e-10){let E=e<.8?M:Math.PI;for(let i=0;i<60;i++){const d=(E-e*Math.sin(E)-M)/(1-e*Math.cos(E));E-=d;if(Math.abs(d)<tol)break;}return E;}
export function gmst(date:Date){
  const jd=date.getTime()/86400000+2440587.5,T=(jd-2451545)/36525;
  let g=280.46061837+360.98564736629*(jd-2451545)+.000387933*T*T-(T*T*T)/38710000;
  g=((g%360)+360)%360;return g*DEG;
}
export function propagateEci(tle:Tle,at:Date):{r:Vec3;v:Vec3}{
  const dt=(at.getTime()-tle.epoch.getTime())/1000,{a,raanDot,argpDot,mDot}=j2Rates(tle);
  const raan=tle.raan+raanDot*dt,argp=tle.argPerigee+argpDot*dt,M=(tle.meanAnomaly+mDot*dt)%TWO_PI;
  const e=tle.eccentricity,E=kepler(((M%TWO_PI)+TWO_PI)%TWO_PI,e);
  const xp=a*(Math.cos(E)-e),yp=a*Math.sqrt(1-e*e)*Math.sin(E),r=a*(1-e*Math.cos(E)),n=Math.sqrt(MU/(a*a*a));
  const vxp=(-a*n*Math.sin(E))/(1-e*Math.cos(E)),vyp=(a*n*Math.sqrt(1-e*e)*Math.cos(E))/(1-e*Math.cos(E));
  const cO=Math.cos(raan),sO=Math.sin(raan),ci=Math.cos(tle.inclination),si=Math.sin(tle.inclination),cw=Math.cos(argp),sw=Math.sin(argp);
  const R11=cO*cw-sO*sw*ci,R12=-cO*sw-sO*cw*ci,R21=sO*cw+cO*sw*ci,R22=-sO*sw+cO*cw*ci,R31=sw*si,R32=cw*si;
  return {r:{x:R11*xp+R12*yp,y:R21*xp+R22*yp,z:R31*xp+R32*yp},v:{x:R11*vxp+R12*vyp,y:R21*vxp+R22*vyp,z:R31*vxp+R32*vyp}};
}
export function eciToEcef(r:Vec3,at:Date):Vec3{
  const g=gmst(at),c=Math.cos(g),s=Math.sin(g);return{x:r.x*c+r.y*s,y:-r.x*s+r.y*c,z:r.z};
}
export function ecefToGeodetic(p:Vec3){
  const a=6378.137,f=1/298.257223563,e2=f*(2-f),lon=Math.atan2(p.y,p.x),rr=Math.hypot(p.x,p.y);
  let lat=Math.atan2(p.z,rr*(1-e2)),alt=0,N=a;
  for(let i=0;i<5;i++){const sl=Math.sin(lat);N=a/Math.sqrt(1-e2*sl*sl);alt=rr/Math.cos(lat)-N;lat=Math.atan2(p.z,rr*(1-e2*N/(N+alt)));}
  return{lat:lat/DEG,lon:lon/DEG,altKm:alt};
}
export function geodeticToEcef(lat:number,lon:number,altKm=0):Vec3{
  const a=6378.137,f=1/298.257223563,e2=f*(2-f),ph=lat*DEG,la=lon*DEG,N=a/Math.sqrt(1-e2*Math.sin(ph)**2);
  return{x:(N+altKm)*Math.cos(ph)*Math.cos(la),y:(N+altKm)*Math.cos(ph)*Math.sin(la),z:(N*(1-e2)+altKm)*Math.sin(ph)};
}
export interface LookAngle{azimuth:number;elevation:number;rangeKm:number}
export function lookAngles(satEcef:Vec3,obsLat:number,obsLon:number,obsAltKm=0):LookAngle{
  const o=geodeticToEcef(obsLat,obsLon,obsAltKm),d=sub(satEcef,o),ph=obsLat*DEG,la=obsLon*DEG;
  const sP=Math.sin(ph),cP=Math.cos(ph),sL=Math.sin(la),cL=Math.cos(la);
  const east=-sL*d.x+cL*d.y,north=-sP*cL*d.x-sP*sL*d.y+cP*d.z,up=cP*cL*d.x+cP*sL*d.y+sP*d.z;
  const range=Math.hypot(east,north,up),el=Math.asin(up/range)/DEG;let az=Math.atan2(east,north)/DEG;if(az<0)az+=360;
  return{azimuth:az,elevation:el,rangeKm:range};
}
export interface Pass{aos:Date;los:Date;tca:Date;maxElevation:number;minRangeKm:number;startAzimuth:number;endAzimuth:number}
export function predictPasses(tle:Tle,obs:{lat:number;lon:number;altKm?:number},from:Date,hours=72,minElevation=5,stepS=20):Pass[]{
  const passes:Pass[]=[],end=from.getTime()+hours*3600000;
  const el=(t:number)=>{const d=new Date(t),ecef=eciToEcef(propagateEci(tle,d).r,d);return lookAngles(ecef,obs.lat,obs.lon,obs.altKm??0);};
  const bisect=(t0:number,t1:number,target:number)=>{for(let i=0;i<40;i++){const m=(t0+t1)/2;if((el(t0).elevation-target)*(el(m).elevation-target)<=0)t1=m;else t0=m;}return(t0+t1)/2;};
  let prev=el(from.getTime()),prevT=from.getTime(),inPass=prev.elevation>=minElevation,passStart=inPass?prevT:0;
  let peak={el:prev.elevation,t:prevT,la:prev};
  for(let t=prevT+stepS*1000;t<=end;t+=stepS*1000){
    const cur=el(t),nowIn=cur.elevation>=minElevation;
    if(!inPass&&nowIn){passStart=bisect(prevT,t,minElevation);peak={el:cur.elevation,t,la:cur};inPass=true;}
    else if(inPass&&nowIn){if(cur.elevation>peak.el)peak={el:cur.elevation,t,la:cur};}
    else if(inPass&&!nowIn){
      const passEnd=bisect(prevT,t,minElevation),startLa=el(passStart);
      passes.push({aos:new Date(passStart),los:new Date(passEnd),tca:new Date(peak.t),maxElevation:+peak.el.toFixed(3),
        minRangeKm:+peak.la.rangeKm.toFixed(3),startAzimuth:+startLa.azimuth.toFixed(2),endAzimuth:+el(passEnd).azimuth.toFixed(2)});
      inPass=false;
    }
    prev=cur;prevT=t;
  }
  return passes;
}
export function footprintRadiusKm(altKm:number,minElevationDeg=0){
  const ep=minElevationDeg*DEG,eta=Math.asin((RE/(RE+altKm))*Math.cos(ep));return RE*(Math.PI/2-ep-eta);
}
export function groundFootprint(tle:Tle,at:Date,minEl=0){
  const ecef=eciToEcef(propagateEci(tle,at).r,at),geo=ecefToGeodetic(ecef);return{...geo,radiusKm:footprintRadiusKm(geo.altKm,minEl)};
}
export function haversineKm(lat1:number,lon1:number,lat2:number,lon2:number){
  const R=6371.0088,dLat=(lat2-lat1)*DEG,dLon=(lon2-lon1)*DEG;
  const a=Math.sin(dLat/2)**2+Math.cos(lat1*DEG)*Math.cos(lat2*DEG)*Math.sin(dLon/2)**2;
  return 2*R*Math.asin(Math.sqrt(a));
}
export function footprintCovers(tle:Tle,at:Date,lat:number,lon:number,minEl=0){
  const fp=groundFootprint(tle,at,minEl);return haversineKm(fp.lat,fp.lon,lat,lon)<=fp.radiusKm;
}
export function imagingOpportunities(tles:Tle[],lat:number,lon:number,from:Date,hours=48,minEl=20){
  const out:Array<{noradId:number;name:string;pass:Pass}>=[];for(const t of tles)for(const p of predictPasses(t,{lat,lon},from,hours,minEl,30))
    out.push({noradId:t.noradId,name:t.name,pass:p});
  return out.sort((a,b)=>a.pass.aos.getTime()-b.pass.aos.getTime());
}
