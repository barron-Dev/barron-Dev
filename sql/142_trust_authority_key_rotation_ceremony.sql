-- Cyclothone Trust v1: authority key rotation, ceremony lifecycle, and audit hardening.

begin;

create table if not exists public.trust_public_key_lifecycle_events (
  id uuid primary key default gen_random_uuid(),
  key_id text not null,
  purpose text not null,
  event_type text not null,
  ceremony_id uuid null references public.trust_public_key_ceremonies(id),
  actor text not null default 'service_role',
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  constraint trust_public_key_lifecycle_event_type_chk
    check (event_type in ('CEREMONY_ISSUED','KEY_ACTIVATED','KEY_RETIRED','KEY_REVOKED','KEY_REACTIVATION_BLOCKED'))
);

create index if not exists trust_public_key_lifecycle_events_key_idx
  on public.trust_public_key_lifecycle_events(key_id, created_at desc);

create index if not exists trust_public_key_lifecycle_events_ceremony_idx
  on public.trust_public_key_lifecycle_events(ceremony_id);

alter table public.trust_public_key_lifecycle_events enable row level security;

drop policy if exists trust_public_key_lifecycle_events_member_read on public.trust_public_key_lifecycle_events;
create policy trust_public_key_lifecycle_events_member_read
  on public.trust_public_key_lifecycle_events
  for select to authenticated
  using (auth.role() = 'authenticated');

revoke insert, update, delete on public.trust_public_key_lifecycle_events from anon, authenticated;

create unique index if not exists trust_public_key_directory_one_active_per_purpose
  on public.trust_public_key_directory(purpose)
  where status='ACTIVE';

create or replace function public.trust_issue_public_key_ceremony(
  p_key_id text,
  p_purpose text,
  p_ttl_seconds integer default 600
) returns jsonb
language plpgsql security definer set search_path=public,'pg_catalog'
as $function$
declare v_id uuid; v_nonce text; v_hash text; v_expires timestamptz; v_existing text;
begin
  if auth.role() <> 'service_role' then raise exception 'service_role_required'; end if;
  if nullif(trim(p_key_id),'') is null then raise exception 'key_id_required'; end if;
  if p_purpose not in ('TRUST_PROOF','TRUST_CERTIFICATE','TRUST_ATTESTATION','TRUST_EVIDENCE','TRUST_AUTHORITY') then
    raise exception 'invalid_public_key_purpose';
  end if;
  if p_ttl_seconds < 60 or p_ttl_seconds > 3600 then raise exception 'invalid_ceremony_ttl'; end if;

  select status into v_existing from public.trust_public_key_directory where key_id=trim(p_key_id);
  if v_existing='REVOKED' then raise exception 'revoked_key_id_cannot_be_reused'; end if;

  v_nonce := encode(gen_random_bytes(32),'hex');
  v_hash := encode(digest(convert_to(jsonb_build_object(
    'protocol','cyclothone-trust-key-ceremony-v1',
    'key_id',trim(p_key_id),'purpose',p_purpose,'nonce',v_nonce
  )::text,'utf8'),'sha256'),'hex');
  v_expires := now() + make_interval(secs => p_ttl_seconds);

  insert into public.trust_public_key_ceremonies(key_id,purpose,challenge_hash,expires_at)
  values(trim(p_key_id),p_purpose,v_hash,v_expires) returning id into v_id;

  insert into public.trust_public_key_lifecycle_events(key_id,purpose,event_type,ceremony_id,metadata)
  values(trim(p_key_id),p_purpose,'CEREMONY_ISSUED',v_id,
         jsonb_build_object('expires_at',v_expires,'protocol','cyclothone-trust-key-ceremony-v1'));

  return jsonb_build_object('ceremony_id',v_id,'protocol','cyclothone-trust-key-ceremony-v1',
    'key_id',trim(p_key_id),'purpose',p_purpose,'nonce',v_nonce,
    'challenge_hash',v_hash,'expires_at',v_expires);
end;
$function$;

create or replace function public.trust_activate_public_key_ceremony(
  p_ceremony_id uuid,
  p_public_key text,
  p_verification_hash text
) returns text
language plpgsql security definer set search_path=public,'pg_catalog'
as $function$
declare
  c public.trust_public_key_ceremonies%rowtype;
  existing public.trust_public_key_directory%rowtype;
begin
  if current_user <> 'service_role' then raise exception 'service_role_required'; end if;
  select * into c from public.trust_public_key_ceremonies where id=p_ceremony_id for update;
  if not found then raise exception 'ceremony_not_found'; end if;
  if c.status<>'ISSUED' then raise exception 'ceremony_not_active'; end if;
  if c.expires_at<=now() then raise exception 'ceremony_expired'; end if;
  if length(p_public_key)<>64 or p_public_key !~ '^[0-9a-fA-F]{64}$' then raise exception 'invalid_ed25519_public_key'; end if;
  if length(p_verification_hash)<>64 or p_verification_hash !~ '^[0-9a-fA-F]{64}$' then raise exception 'invalid_verification_hash'; end if;

  select * into existing from public.trust_public_key_directory where key_id=c.key_id for update;
  if existing.id is not null and existing.status='REVOKED' then
    insert into public.trust_public_key_lifecycle_events(key_id,purpose,event_type,ceremony_id,metadata)
    values(c.key_id,c.purpose,'KEY_REACTIVATION_BLOCKED',p_ceremony_id,
           jsonb_build_object('reason','revoked_key_id_cannot_be_reused'));
    raise exception 'revoked_key_id_cannot_be_reused';
  end if;

  update public.trust_public_key_directory
     set status='RETIRED', metadata=metadata||jsonb_build_object(
       'retired_by_ceremony',p_ceremony_id,'retired_at',now())
   where purpose=c.purpose and status='ACTIVE' and key_id<>c.key_id;

  if existing.id is null then
    insert into public.trust_public_key_directory(
      key_id,algorithm,purpose,public_key,status,metadata
    ) values(
      c.key_id,'ED25519',c.purpose,lower(p_public_key),'ACTIVE',
      jsonb_build_object('ceremony_id',p_ceremony_id,'verification_hash',p_verification_hash)
    );
  else
    update public.trust_public_key_directory
       set algorithm='ED25519', purpose=c.purpose, public_key=lower(p_public_key),
           status='ACTIVE', revoked_at=null,
           metadata=metadata||jsonb_build_object('ceremony_id',p_ceremony_id,
                                                  'verification_hash',p_verification_hash)
     where id=existing.id;
  end if;

  update public.trust_public_key_ceremonies set status='CONSUMED',consumed_at=now()
   where id=p_ceremony_id;

  insert into public.trust_public_key_lifecycle_events(key_id,purpose,event_type,ceremony_id,metadata)
  values(c.key_id,c.purpose,'KEY_ACTIVATED',p_ceremony_id,
         jsonb_build_object('verification_hash',p_verification_hash,'algorithm','ED25519'));

  return c.key_id;
end;
$function$;

create or replace function public.trust_retire_public_key(p_key_id text)
returns boolean language plpgsql security definer set search_path=public,'pg_catalog'
as $function$
declare v_purpose text; v_changed boolean;
begin
  if current_user<>'service_role' then raise exception 'service_role_required'; end if;
  update public.trust_public_key_directory
     set status='RETIRED',metadata=metadata||jsonb_build_object('retired_at',now())
   where key_id=p_key_id and status='ACTIVE'
   returning purpose into v_purpose;
  v_changed := found;
  if v_changed then
    insert into public.trust_public_key_lifecycle_events(key_id,purpose,event_type,metadata)
    values(p_key_id,v_purpose,'KEY_RETIRED','{}'::jsonb);
  end if;
  return v_changed;
end;
$function$;

create or replace function public.trust_revoke_public_key(p_key_id text)
returns boolean language plpgsql security definer set search_path=public,'pg_catalog'
as $function$
declare v_purpose text; v_changed boolean;
begin
  if auth.role()<>'service_role' then raise exception 'service_role_required'; end if;
  update public.trust_public_key_directory
     set status='REVOKED',revoked_at=coalesce(revoked_at,now())
   where key_id=p_key_id and status<>'REVOKED'
   returning purpose into v_purpose;
  v_changed := found;
  if v_changed then
    insert into public.trust_public_key_lifecycle_events(key_id,purpose,event_type,metadata)
    values(p_key_id,v_purpose,'KEY_REVOKED',jsonb_build_object('revoked_at',now()));
  end if;
  return v_changed;
end;
$function$;

commit;
