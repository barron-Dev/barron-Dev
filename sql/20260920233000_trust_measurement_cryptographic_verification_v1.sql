-- Cryptographic verification audit for immutable runtime measurements.
create table if not exists public.trust_measurement_verification_events (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  measurement_id uuid not null references public.trust_measurements(id) on delete restrict,
  subject_id uuid not null references public.trust_subjects(id) on delete restrict,
  verification_status text not null check (verification_status in ('VERIFIED','FAILED','EXPIRED','REVOKED')),
  verification_method text not null,
  verification_hash text not null check (verification_hash ~ '^[0-9a-fA-F]{64}$'),
  signed_payload_hash text,
  signer_key_id text,
  failure_reason text,
  verified_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);
alter table public.trust_measurement_verification_events enable row level security;
revoke all on public.trust_measurement_verification_events from public,anon,authenticated;
grant select on public.trust_measurement_verification_events to service_role;
drop policy if exists trust_measurement_verification_events_deny on public.trust_measurement_verification_events;
create policy trust_measurement_verification_events_deny on public.trust_measurement_verification_events for all to anon, authenticated using (false) with check (false);
create or replace function public.trust_record_measurement_verification(
 p_tenant_id uuid,p_measurement_id uuid,p_verified boolean,p_verification_hash text,
 p_verification_method text,p_signed_payload_hash text default null,p_signer_key_id text default null,
 p_failure_reason text default null
) returns uuid language plpgsql security definer set search_path='public','pg_catalog'
as $function$
declare m public.trust_measurements; s public.trust_subjects; eid uuid; status text;
begin
 if p_tenant_id is null or p_measurement_id is null or p_verification_method is null
    or p_verification_hash is null or p_verification_hash !~ '^[0-9a-fA-F]{64}$'
 then raise exception 'invalid_measurement_verification'; end if;
 select * into m from public.trust_measurements where id=p_measurement_id;
 if not found then raise exception 'trust_measurement_not_found'; end if;
 select * into s from public.trust_subjects where id=m.subject_id;
 if not found or s.tenant_id<>p_tenant_id or m.tenant_id<>p_tenant_id
 then raise exception 'trust_measurement_tenant_mismatch'; end if;
 status := case when p_verified then 'VERIFIED' else 'FAILED' end;
 insert into public.trust_measurement_verification_events(
   tenant_id,measurement_id,subject_id,verification_status,verification_method,
   verification_hash,signed_payload_hash,signer_key_id,failure_reason
 ) values (
   p_tenant_id,m.id,m.subject_id,status,p_verification_method,p_verification_hash,
   p_signed_payload_hash,p_signer_key_id,nullif(left(coalesce(p_failure_reason,''),2000),'')
 ) returning id into eid;
 return eid;
end;$function$;
revoke all on function public.trust_record_measurement_verification(uuid,uuid,boolean,text,text,text,text,text) from public,anon,authenticated;
grant execute on function public.trust_record_measurement_verification(uuid,uuid,boolean,text,text,text,text,text) to service_role;