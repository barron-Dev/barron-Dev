import { NextRequest,NextResponse } from 'next/server';
import { overflightAttribution } from '@/lib/mdi/services/satelliteIntel';
import { authError,requireMdiClearance } from '@/lib/mdi/auth';
export async function POST(req:NextRequest){try{const {sb}=await requireMdiClearance(req);const {lat,lon,from,to,minElevation=10}=await req.json();if(!Number.isFinite(lat)||!Number.isFinite(lon)||!from||!to)return NextResponse.json({error:'lat_lon_from_to_required'},{status:400});const hits=await overflightAttribution(sb,lat,lon,new Date(from),new Date(to),minElevation);return NextResponse.json({hits,count:hits.length});}catch(e){const x=authError(e);return NextResponse.json({error:x.error},{status:x.status});}}
