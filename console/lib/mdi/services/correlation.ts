import type { SupabaseClient } from '@supabase/supabase-js';
import { buildAdjacency,shortestPath,pageRank,labelPropagation,jaccard,adamicAdar } from '../algorithms/graph';
import { propagateRisk } from '../algorithms/risk';
export interface CorrelationReport{pagerank:Array<{id:string;score:number}>;communities:Array<{label:string;members:string[]}>;paths:Record<string,{path:string[];kinds:string[];cost:number}|null>;predictedLinks:Array<{a:string;b:string;jaccard:number;adamicAdar:number}>;propagatedRisk:Record<string,number>}
export async function correlate(sb:SupabaseClient,seedIds:string[],hops=3,minWeight=.05):Promise<CorrelationReport>{
 if(!seedIds.length)throw new Error('seed_required');
 const {data:nb,error}=await sb.rpc('mdi_neighborhood',{p_subject:seedIds[0],p_hops:hops,p_min_weight:minWeight});if(error)throw error;
 const ids=new Set<string>([...seedIds,...(nb??[]).map((r:any)=>r.subject_id)]);const {data:edges,error:eErr}=await sb.from('mdi_graph_edges').select('id,src_id,dst_id,kind,weight,confidence,observations,last_seen').in('src_id',[...ids]).in('dst_id',[...ids]).gte('weight',minWeight);if(eErr)throw eErr;
 const edgeList=(edges??[]).map((e:any)=>({src:e.src_id,dst:e.dst_id,weight:Number(e.weight),confidence:Number(e.confidence),kind:String(e.kind)}));const adj=buildAdjacency(edgeList,false);
 const pr=pageRank(adj,40,.85);const pagerank=[...pr.entries()].map(([id,score])=>({id,score:+score.toFixed(8)})).sort((a,b)=>b.score-a.score);
 const labels=labelPropagation(adj,60),buckets=new Map<string,string[]>();for(const [node,label] of labels){if(!buckets.has(label))buckets.set(label,[]);buckets.get(label)!.push(node)}const communities=[...buckets.entries()].filter(([,m])=>m.length>1).map(([label,members])=>({label,members})).sort((a,b)=>b.members.length-a.members.length);
 const paths:CorrelationReport['paths']={};for(let i=0;i<seedIds.length;i++)for(let j=i+1;j<seedIds.length;j++)paths[`${seedIds[i]}→${seedIds[j]}`]=shortestPath(adj,seedIds[i],seedIds[j],minWeight);
 const nodes=[...adj.keys()],predictedLinks:CorrelationReport['predictedLinks']=[];for(let i=0;i<nodes.length;i++)for(let j=i+1;j<nodes.length;j++){const jac=jaccard(nodes[i],nodes[j],adj);if(jac<.25)continue;predictedLinks.push({a:nodes[i],b:nodes[j],jaccard:+jac.toFixed(4),adamicAdar:+adamicAdar(nodes[i],nodes[j],adj).toFixed(4)})}predictedLinks.sort((a,b)=>b.adamicAdar-a.adamicAdar);
 const {data:subj}=await sb.from('mdi_subjects').select('id,risk_score').in('id',[...ids]);const ownRisk=new Map((subj??[]).map((s:any)=>[s.id,Number(s.risk_score)]));const prop=propagateRisk(ownRisk,edgeList,.35,4);
 const toPersist=communities.slice(0,20).map(c=>({correlation_type:'community',subject_ids:c.members,strength:+(c.members.length/Math.max(nodes.length,1)).toFixed(4),algorithm:'label_propagation',explanation:{size:c.members.length,label:c.label}}));if(toPersist.length){const {error}=await sb.from('mdi_correlations').insert(toPersist);if(error)throw error;}
 return {pagerank,communities,paths,predictedLinks:predictedLinks.slice(0,100),propagatedRisk:Object.fromEntries([...prop.entries()].map(([k,v])=>[k,+v.toFixed(2)]))};
}
