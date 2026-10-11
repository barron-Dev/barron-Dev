-- Attempt-fenced provider progress for customer Dark Web requests.
-- Progress reflects completed provider checks, not estimated elapsed time.
create or replace function public.record_service_request_source_progress(
    p_id uuid,
    p_attempt integer,
    p_source_id text,
    p_state text,
    p_reason text default null,
    p_total_sources integer default 5
) returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
    v_result jsonb;
    v_progress jsonb;
    v_completed integer;
    v_total integer := greatest(coalesce(p_total_sources, 5), 1);
begin
    if p_source_id not in ('ransomwatch','hibp','github_code','pastebin_public','telegram_public')
       or p_state not in ('checked','unavailable','failed') then
        raise exception 'invalid_source_progress';
    end if;

    select coalesce(result, '{}'::jsonb)
      into v_result
      from public.service_requests
     where id = p_id
       and attempts = p_attempt
       and processing_state = 'running'
     for update;

    if not found then
        return false;
    end if;

    v_progress := coalesce(v_result->'sources_progress', '[]'::jsonb);
    select coalesce(jsonb_agg(item), '[]'::jsonb)
      into v_progress
      from jsonb_array_elements(v_progress) as entries(item)
     where not (
        item->>'attempt' = p_attempt::text
        and item->>'source' = p_source_id
     );

    v_progress := v_progress || jsonb_build_array(jsonb_strip_nulls(jsonb_build_object(
        'attempt', p_attempt,
        'source', p_source_id,
        'state', p_state,
        'reason', p_reason,
        'updated_at', now()
    )));

    select count(distinct item->>'source')
      into v_completed
      from jsonb_array_elements(v_progress) as entries(item)
     where item->>'attempt' = p_attempt::text;

    v_result := jsonb_set(v_result, '{sources_progress}', v_progress, true);
    v_result := jsonb_set(v_result, '{progress_percent}', to_jsonb(least(100, floor(100.0 * v_completed / v_total)::integer)), true);
    v_result := jsonb_set(v_result, '{progress_stage}', to_jsonb('checking_sources'::text), true);

    update public.service_requests
       set result = v_result, updated_at = now()
     where id = p_id
       and attempts = p_attempt
       and processing_state = 'running';

    return found;
end;
$$;

revoke all on function public.record_service_request_source_progress(uuid, integer, text, text, text, integer) from public, anon, authenticated;
grant execute on function public.record_service_request_source_progress(uuid, integer, text, text, text, integer) to service_role;
