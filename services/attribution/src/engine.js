export function jaccard(a,b){
  const aa=new Set(a),bb=new Set(b);
  let inter=0;
  for(const x of aa) if(bb.has(x)) inter++;
  const union=aa.size+bb.size-inter;
  return union?inter/union:0;
}

export function naiveBayes(caseTtps,actors,spaceSize){
  const alpha=0.1;
  const scores=actors.map(a=>{
    const prior=1/Math.max(actors.length,1);
    let logP=Math.log(prior);
    for(const t of caseTtps){
      const count=a.ttps.has(t)?1:0;
      logP+=Math.log((count+alpha)/(a.ttps.size+alpha*spaceSize));
    }
    return {actor:a,logP};
  });
  const max=Math.max(...scores.map(s=>s.logP));
  const exp=scores.map(s=>Math.exp(s.logP-max));
  const sum=exp.reduce((a,b)=>a+b,0)||1;
  return scores.map((s,i)=>({actor:s.actor,prob:exp[i]/sum}));
}

export function combine(caseTtps,actors,spaceSize){
  const bayes=naiveBayes(caseTtps,actors,spaceSize);
  return actors.map(actor=>{
    const j=jaccard(caseTtps,actor.ttps);
    const b=bayes.find(x=>x.actor.id===actor.id)?.prob??0;
    return {actorId:actor.actorId,actorUuid:actor.id,name:actor.name,jaccard:j,bayesProb:b,combined:Math.sqrt(j*b),sharedTtps:caseTtps.filter(t=>actor.ttps.has(t))};
  }).filter(x=>x.jaccard>0||x.bayesProb>0).sort((a,b)=>b.combined-a.combined);
}