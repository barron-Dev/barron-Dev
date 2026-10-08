import { NextRequest,NextResponse } from 'next/server';
import { correlate } from '@/lib/mdi/services/correlation';
import { authError,requireMdiClearance } from '@/server/mdi/auth';
export async function POST(req:NextRequest){try{const {sb}=await requireMdiClearance(req);const {subjectIds,hops=3,minWeight=.05}=await req.json();if(!Array.isArray(subjectIds)||!subjectIds.length)return NextResponse.json({error:'subjectIds_required'},{status:400});const report=await correlate(sb,subjectIds,hops,minWeight);return NextResponse.json(report);}catch(e){const x=authError(e);return NextResponse.json({error:x.error},{status:x.status});}}
