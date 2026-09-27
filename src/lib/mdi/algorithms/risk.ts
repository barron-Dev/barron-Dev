export interface RiskSignal {
  k: string; lr: number; w?: number; conf?: number; ageS?: number; halfLifeS?: number;
}
export interface RiskResult {
  score: number;
  band: 'unknown' | 'low' | 'medium' | 'high' | 'critical';
  logOdds: number;
  probability: number;
  breakdown: Array<{ k: string; lr: number; effLr: number; contrib: number }>;
}
const sigmoid=(x:number)=>1/(1+Math.exp(-x));
const logit=(p:number)=>Math.log(p/(1-p));
const clamp=(x:number,lo:number,hi:number)=>Math.min(hi,Math.max(lo,x));
export function bandFor(p:number):RiskResult['band']{
  if(p>=.90)return'critical'; if(p>=.70)return'high'; if(p>=.40)return'medium'; if(p>=.10)return'low'; return'unknown';
}
export function fuseRisk(prior:number,signals:RiskSignal[]):RiskResult{
  const p0=clamp(prior,1e-6,1-1e-6); let lo=logit(p0);
  const breakdown:RiskResult['breakdown']=[];
  for(const s of signals){
    const w=s.w??1,c=clamp(s.conf??1,0,1);
    const decay=s.halfLifeS&&s.halfLifeS>0?Math.pow(.5,Math.max(s.ageS??0,0)/s.halfLifeS):1;
    const effLr=Math.max(1+(s.lr-1)*c*decay,1e-4), contrib=w*Math.log(effLr);
    lo+=contrib; breakdown.push({k:s.k,lr:s.lr,effLr:+effLr.toFixed(4),contrib:+contrib.toFixed(4)});
  }
  const p=sigmoid(clamp(lo,-60,60));
  breakdown.sort((a,b)=>Math.abs(b.contrib)-Math.abs(a.contrib));
  return {score:+(p*100).toFixed(2),band:bandFor(p),logOdds:+lo.toFixed(4),probability:p,breakdown};
}
export function propagateRisk(
  nodes:Map<string,number>,
  edges:Array<{src:string;dst:string;weight:number;conf:number}>,
  damping=.35,iterations=3,
):Map<string,number>{
  let current=new Map(nodes);
  for(let it=0;it<iterations;it++){
    const next=new Map(current),acc=new Map<string,number>(),wsum=new Map<string,number>();
    for(const e of edges){
      const influence=e.weight*e.conf;
      acc.set(e.dst,(acc.get(e.dst)??0)+(current.get(e.src)??0)*influence);
      wsum.set(e.dst,(wsum.get(e.dst)??0)+influence);
      acc.set(e.src,(acc.get(e.src)??0)+(current.get(e.dst)??0)*influence);
      wsum.set(e.src,(wsum.get(e.src)??0)+influence);
    }
    for(const [id,own] of current){
      const nb=wsum.get(id)??0, propagated=nb>0?(acc.get(id)??0)/nb:0;
      next.set(id,clamp(own*(1-damping)+propagated*damping,0,100));
    }
    current=next;
  }
  return current;
}
