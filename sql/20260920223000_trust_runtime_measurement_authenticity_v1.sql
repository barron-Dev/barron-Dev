-- Runtime measurement authenticity extension.
-- Extends the existing measurement primitive; no parallel measurement registry.

alter table public.trust_measurements
  add column if not exists signature_algorithm text,
  add column if not exists signer_key_id text,
  add column if not exists signature text,
  add column if not exists signed_payload_hash text,
  add column if not exists verification_status text not null default 'UNVERIFIED',
  add column if not exists verification_method text,
  add column if not exists verification_hash text,
  add column if not exists verification_failure_reason text;

alter table public.trust_measurements
  drop constraint if exists trust_measurements_verification_status_check;
alter table public.trust_measurements
  add constraint trust_measurements_verification_status_check
  check (verification_status in ('UNVERIFIED','VERIFIED','FAILED'));

alter table public.trust_measurements
  drop constraint if exists trust_measurements_signed_payload_hash_check;
alter table public.trust_measurements
  add constraint trust_measurements_signed_payload_hash_check
  check (signed_payload_hash is null or signed_payload_hash ~ '^[0-9a-fA-F]{64}$');

alter table public.trust_measurements
  drop constraint if exists trust_measurements_verification_hash_check;
alter table public.trust_measurements
  add constraint trust_measurements_verification_hash_check
  check (verification_hash is null or verification_hash ~ '^[0-9a-fA-F]{64}$');

drop function if exists public.trust_record_measurement(uuid,text,text,text,text,text,timestamptz,text,text,jsonb);

create function public.trust_record_measurement(
  p_subject_id uuid,
  p_measurement_type text,
  p_algorithm text,
  p_measurement_value text,
  p_source_type text,
  p_source_id text default null,
  p_collected_at timestamptz default now(),
  p_evidence_uri text default null,
  p_evidence_hash text default null,
  p_metadata jsonb default '{}'::jsonb,
  p_signature_algorithm text default null,
  p_signer_key_id text default null,
  p_signature text default null,
  p_signed_payload_hash text default null,
  p_verification_status text default 'UNVERIFIED',
  p_verification_method text default null,
  p_verification_hash text default null,
  p_verification_failure_reason text default null
) returns public.trust_measurements
language plpgsql security definer
set search_path to 'public','pg_catalog'
as $function$
declare
  s public.trust_subjects;
  m public.trust_measurements;
  h text;
begin
  if p_subject_id is null or p_measurement_type is null or p_algorithm is null
     or p_measurement_value is null or p_source_type is null or p_collected_at is null
     or jsonb_typeof(coalesce(p_metadata,'{}'::jsonb)) <> 'object' then
    raise exception 'invalid_trust_measurement';
  end if;
  if p_verification_status not in ('UNVERIFIED','VERIFIED','FAILED') then
    raise exception 'invalid_measurement_verification_status';
  end if;
  if p_verification_status='VERIFIED' and (
    p_signature_algorithm is null or p_signer_key_id is null or p_signature is null
    or p_signed_payload_hash is null or p_verification_method is null or p_verification_hash is null
  ) then
    raise exception 'verified_measurement_requires_cryptographic_evidence';
  end if;
  if p_signed_payload_hash is not null and p_signed_payload_hash !~ '^[0-9a-fA-F]{64}$' then
    raise exception 'invalid_measurement_signed_payload_hash';
  end if;
  if p_verification_hash is not null and p_verification_hash !~ '^[0-9a-fA-F]{64}$' then
    raise exception 'invalid_measurement_verification_hash';
  end if;

  select * into s from public.trust_subjects where id=p_subject_id for share;
  if not found then raise exception 'trust_subject_not_found'; end if;
  if s.lifecycle_state in ('REVOKED','EXPIRED') then raise exception 'trust_subject_not_measureable'; end if;

  h := public.trust_measurement_hash(
    p_subject_id,p_measurement_type,p_algorithm,p_measurement_value,
    p_source_type,p_source_id,p_collected_at,p_evidence_hash
  );

  insert into public.trust_measurements(
    subject_id,tenant_id,measurement_type,algorithm,measurement_value,measurement_hash,
    source_type,source_id,collected_at,evidence_uri,evidence_hash,metadata,
    signature_algorithm,signer_key_id,signature,signed_payload_hash,
    verification_status,verification_method,verification_hash,verification_failure_reason
  )
  values (
    p_subject_id,s.tenant_id,p_measurement_type,p_algorithm,p_measurement_value,h,
    p_source_type,p_source_id,p_collected_at,p_evidence_uri,p_evidence_hash,coalesce(p_metadata,'{}'::jsonb),
    p_signature_algorithm,p_signer_key_id,p_signature,p_signed_payload_hash,
    p_verification_status,p_verification_method,p_verification_hash,
    nullif(left(coalesce(p_verification_failure_reason,''),2000),'')
  )
  on conflict (subject_id,measurement_type,measurement_hash,collected_at)
  do update set received_at=public.trust_measurements.received_at
  returning * into m;

  return m;
end;
$function$;

revoke all on function public.trust_record_measurement(uuid,text,text,text,text,text,timestamptz,text,text,jsonb,text,text,text,text,text,text,text,text) from public,anon,authenticated;
grant execute on function public.trust_record_measurement(uuid,text,text,text,text,text,timestamptz,text,text,jsonb,text,text,text,text,text,text,text,text) to service_role;