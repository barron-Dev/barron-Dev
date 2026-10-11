-- Fix the PL/pgSQL output-column ambiguity in dark-web alert upserts.
-- Use the named unique constraint so the RETURNS TABLE output variable finding_id
-- cannot conflict with the dw_alerts column reference.
do $migration$
declare
  v_definition text;
  v_old text := 'ON CONFLICT (watchlist_id, finding_id) DO UPDATE';
  v_new text := 'ON CONFLICT ON CONSTRAINT dw_alerts_watchlist_id_finding_id_key DO UPDATE';
begin
  v_definition := pg_get_functiondef(
    'public.record_dw_finding(text,text,text,text,text,text,text,jsonb,uuid,uuid)'::regprocedure
  );
  if position(v_old in v_definition) = 0 then
    if position(v_new in v_definition) > 0 then
      null; -- already corrected; safe to re-run
    else
      raise exception 'record_dw_finding definition did not contain expected alert upsert';
    end if;
  else
    execute replace(v_definition, v_old, v_new);
  end if;
end
$migration$;

-- HIBP is intentionally excluded from active collection; keep the legacy row for audit.
update public.dw_sources
set enabled = false,
    last_status = 'excluded_by_policy'
where id = 'hibp';
