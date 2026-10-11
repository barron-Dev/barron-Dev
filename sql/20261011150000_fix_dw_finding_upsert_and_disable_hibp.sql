-- Fix the PL/pgSQL output-column ambiguity in dark-web alert upserts.
-- Use the named unique constraint so the RETURNS TABLE output variable finding_id
-- cannot conflict with the dw_alerts column reference.
do $migration$
declare
  v_definition text;
  v_updated text;
begin
  v_definition := pg_get_functiondef(
    'public.record_dw_finding(text,text,text,text,text,text,text,jsonb,uuid,uuid)'::regprocedure
  );
  v_updated := regexp_replace(
    v_definition,
    'on conflict[[:space:]]*\(watchlist_id,[[:space:]]*finding_id\)[[:space:]]*do update',
    'ON CONFLICT ON CONSTRAINT dw_alerts_watchlist_id_finding_id_key DO UPDATE',
    'i'
  );
  if v_updated = v_definition then
    if position('dw_alerts_watchlist_id_finding_id_key' in v_definition) = 0 then
      raise exception 'record_dw_finding definition did not contain expected alert upsert';
    end if;
  else
    execute v_updated;
  end if;
end
$migration$;

-- HIBP is intentionally excluded from active collection; keep the legacy row for audit.
update public.dw_sources
set enabled = false,
    last_status = 'excluded_by_policy'
where id = 'hibp';
