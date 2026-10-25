import { NextRequest, NextResponse } from 'next/server';
import { requireMdiClearance } from '@/server/mdi/auth';

export async function GET(req: NextRequest, { params }: { params: Promise<{ subjectId: string }> }) {
  try {
    const { sb } = await requireMdiClearance(req);
    const { subjectId } = await params;
    const since = new Date(Date.now() - 30 * 86400_000).toISOString();
    const { data, error } = await sb
      .from('mdi_location_signals')
      .select('h3_r7,h3_r9,lat,lon,observed_at,confidence,signal_type')
      .eq('subject_id', subjectId)
      .gte('observed_at', since)
      .order('observed_at', { ascending: false })
      .limit(2000);
    if (error) throw error;
    const cells: Record<string, { count: number; lastSeen: string; confidence: number }> = {};
    for (const row of data ?? []) {
      const key = row.h3_r7 ?? row.h3_r9;
      if (!key) continue;
      const current = cells[key] ?? { count: 0, lastSeen: row.observed_at, confidence: 0 };
      current.count += 1;
      current.lastSeen = current.lastSeen > row.observed_at ? current.lastSeen : row.observed_at;
      current.confidence = Math.max(current.confidence, Number(row.confidence ?? 0));
      cells[key] = current;
    }
    return NextResponse.json({ subjectId, since, cells });
  } catch (error) {
    return NextResponse.json({ error: error instanceof Error ? error.message : 'mdi_internal_error' }, { status: 500 });
  }
}
