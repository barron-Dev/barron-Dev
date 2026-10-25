import { NextRequest, NextResponse } from 'next/server';
import { requireMdiClearance } from '@/server/mdi/auth';

export async function GET(req: NextRequest, { params }: { params: Promise<{ subjectId: string }> }) {
  try {
    const { sb } = await requireMdiClearance(req);
    const { subjectId } = await params;
    const { data, error } = await sb
      .from('mdi_risk_assessments')
      .select('id,subject_id,score,band,prior,log_odds,signals,model_version,computed_at')
      .eq('subject_id', subjectId)
      .order('computed_at', { ascending: false })
      .limit(1)
      .maybeSingle();
    if (error) throw error;
    if (!data) return NextResponse.json({ error: 'risk_not_found' }, { status: 404 });
    return NextResponse.json(data);
  } catch (error) {
    return NextResponse.json({ error: error instanceof Error ? error.message : 'mdi_internal_error' }, { status: 500 });
  }
}
