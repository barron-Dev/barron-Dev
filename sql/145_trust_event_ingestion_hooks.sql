-- 145_trust_event_ingestion_hooks.sql
-- Connect authoritative trust writes to the Block 30 re-evaluation queue.
-- Triggers only enqueue; they never mutate trust state directly.

begin;

create or replace function public.trust_enqueue_measurement_re_evaluation()
returns trigger
language plpgsql
security definer
set search_path=public,pg_catalog
as $function$
begin
  perform public.trust_enqueue_re_evaluation(
    new.subject_id,
    'MEASUREMENT_RECORDED',
    new.id,
    case when new.measurement_hash ~ '^[0-9a-f]{64}$' then new.measurement_hash else null end,
    'new_trust_measurement_recorded'
  );
  return new;
end;
$function$;

create or replace function public.trust_enqueue_evidence_re_evaluation()
returns trigger
language plpgsql
security definer
set search_path=public,pg_catalog
as $function$
declare
  event_type text;
  reason text;
begin
  if tg_op='INSERT' then
    event_type := 'EVIDENCE_RECORDED';
    reason := 'new_trust_evidence_recorded';
  elsif new.verification_status='VERIFIED'
        and old.verification_status is distinct from new.verification_status then
    event_type := 'EVIDENCE_VERIFIED';
    reason := 'trust_evidence_cryptographically_verified';
  elsif new.content_verification_status='VERIFIED'
        and old.content_verification_status is distinct from new.content_verification_status then
    event_type := 'EVIDENCE_CONTENT_VERIFIED';
    reason := 'trust_evidence_content_verified';
  else
    return new;
  end if;

  perform public.trust_enqueue_re_evaluation(
    new.subject_id,
    event_type,
    new.id,
    case when new.evidence_hash ~ '^[0-9a-f]{64}$' then new.evidence_hash else null end,
    reason
  );
  return new;
end;
$function$;

create or replace function public.trust_enqueue_attestation_re_evaluation()
returns trigger
language plpgsql
security definer
set search_path=public,pg_catalog
as $function$
begin
  if tg_op='INSERT'
     or (new.status='VERIFIED' and old.status is distinct from new.status) then
    perform public.trust_enqueue_re_evaluation(
      new.subject_id,
      'ATTESTATION_VERIFIED',
      new.id,
      case when new.attestation_hash ~ '^[0-9a-f]{64}$' then new.attestation_hash else null end,
      'trust_attestation_verified_or_recorded'
    );
  end if;
  return new;
end;
$function$;

drop trigger if exists trust_measurements_enqueue_reevaluation
  on public.trust_measurements;
create trigger trust_measurements_enqueue_reevaluation
after insert on public.trust_measurements
for each row execute function public.trust_enqueue_measurement_re_evaluation();

drop trigger if exists trust_evidence_enqueue_reevaluation
  on public.trust_evidence;
create trigger trust_evidence_enqueue_reevaluation
after insert or update of verification_status,content_verification_status
on public.trust_evidence
for each row execute function public.trust_enqueue_evidence_re_evaluation();

drop trigger if exists trust_attestations_enqueue_reevaluation
  on public.trust_attestations;
create trigger trust_attestations_enqueue_reevaluation
after insert or update of status
on public.trust_attestations
for each row execute function public.trust_enqueue_attestation_re_evaluation();

-- Trigger functions are internal-only.
revoke all on function public.trust_enqueue_measurement_re_evaluation() from public,anon,authenticated;
revoke all on function public.trust_enqueue_evidence_re_evaluation() from public,anon,authenticated;
revoke all on function public.trust_enqueue_attestation_re_evaluation() from public,anon,authenticated;

commit;
