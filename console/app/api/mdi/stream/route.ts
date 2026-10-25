import { NextRequest } from 'next/server';
import { requireMdiClearance } from '@/server/mdi/auth';

export const runtime = 'nodejs';
export const maxDuration = 300;

export async function GET(req: NextRequest) {
  await requireMdiClearance(req);
  const sb = (await requireMdiClearance(req)).sb;
  let lastSeen = new Date(0).toISOString();
  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    async start(controller) {
      const send = (event: string, data: unknown) => {
        controller.enqueue(encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`));
      };
      send('ready', { service: 'mdi', transport: 'sse' });
      const started = Date.now();
      try {
        while (Date.now() - started < 290_000) {
          const { data, error } = await sb
            .from('mdi_advanced_alerts')
            .select('id,alert_type,subject_id,severity,score,action,algorithm,explanation,created_at')
            .gt('created_at', lastSeen)
            .order('created_at', { ascending: true })
            .limit(50);
          if (error) throw error;
          for (const row of data ?? []) {
            lastSeen = row.created_at;
            send('alert', row);
          }
          send('heartbeat', { at: new Date().toISOString() });
          await new Promise(resolve => setTimeout(resolve, 1000));
        }
      } catch (error) {
        send('error', { error: error instanceof Error ? error.message : 'stream_failed' });
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      'content-type': 'text/event-stream; charset=utf-8',
      'cache-control': 'no-cache, no-transform',
      connection: 'keep-alive',
      'x-accel-buffering': 'no',
    },
  });
}
