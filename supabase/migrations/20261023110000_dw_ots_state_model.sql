-- Explicit OTS receipt state machine. Preview only; finding materializers must join this state.
begin;

do $$
begin
  if not exists (
    select 1 from pg_type t join pg_namespace n on n.oid=t.typnamespace
     where n.nspname='public' and t.typname='dw_ots_state'
  ) then
    create type public.dw_ots_state as enum ('pending','confirmed','failed','expired','invalid');
  end if;
end
$$;

alter table public.dw_evidence_ots_receipts
  add column if not exists state public.dw_ots_state;
alter table public.dw_evidence_ots_receipts
  add column if not exists failure_reason text;

-- Never promote a legacy "confirmed" receipt without a block height to confirmed.
update public.dw_evidence_ots_receipts
   set state = case
     when verification_status = 'confirmed' and bitcoin_block_height is not null then 'confirmed'::public.dw_ots_state
     when verification_status = 'confirmed' then 'invalid'::public.dw_ots_state
     when verification_status = 'verification_failed' then 'failed'::public.dw_ots_state
     else 'pending'::public.dw_ots_state
   end,
   failure_reason = case
     when verification_status = 'confirmed' and bitcoin_block_height is null then 'legacy_confirmed_without_block'
     when verification_status = 'verification_failed' then coalesce(failure_reason, 'legacy_verification_failed')
     else failure_reason
   end
 where state is null;

alter table public.dw_evidence_ots_receipts
  alter column state set default 'pending',
  alter column state set not null;

do $$
begin
  if not exists (select 1 from pg_constraint where conname='dw_evidence_ots_failed_has_reason') then
    alter table public.dw_evidence_ots_receipts
      add constraint dw_evidence_ots_failed_has_reason
      check (state <> 'failed' or failure_reason is not null);
  end if;
  if not exists (select 1 from pg_constraint where conname='dw_evidence_ots_confirmed_has_block') then
    alter table public.dw_evidence_ots_receipts
      add constraint dw_evidence_ots_confirmed_has_block
      check (state <> 'confirmed' or bitcoin_block_height is not null);
  end if;
end
$$;

create index if not exists dw_evidence_ots_state_evidence_idx
  on public.dw_evidence_ots_receipts(evidence_seq, state);

create or replace function public.dw_evidence_ots_guard_transition()
returns trigger
language plpgsql
set search_path = pg_catalog, public
as $$
begin
  if new.evidence_seq is distinct from old.evidence_seq
     or new.anchor_id is distinct from old.anchor_id
     or new.proof_uri is distinct from old.proof_uri
     or new.proof_sha256 is distinct from old.proof_sha256
     or new.created_at is distinct from old.created_at then
    raise exception 'OTS receipt artifact identity is immutable' using errcode='55000';
  end if;

  if new.state is distinct from old.state and not (
    old.state = 'pending' and new.state in ('confirmed','failed','expired','invalid')
    or old.state in ('confirmed','failed','expired') and new.state = 'invalid'
  ) then
    raise exception 'invalid OTS state transition: % -> %', old.state, new.state using errcode='22023';
  end if;

  if new.state = 'confirmed' and new.bitcoin_block_height is null then
    raise exception 'confirmed OTS receipt requires a Bitcoin block height' using errcode='23514';
  end if;
  if new.state = 'failed' and new.failure_reason is null then
    raise exception 'failed OTS receipt requires a failure reason' using errcode='23514';
  end if;
  new.verification_status := case
    when new.state = 'pending' then 'pending'
    when new.state = 'confirmed' then 'confirmed'
    else 'verification_failed'
  end;
  return new;
end
$;

drop trigger if exists dw_evidence_ots_state_guard on public.dw_evidence_ots_receipts;
create trigger dw_evidence_ots_state_guard
before update on public.dw_evidence_ots_receipts
for each row execute function public.dw_evidence_ots_guard_transition();

comment on column public.dw_evidence_ots_receipts.state is
  'Verifier-derived OpenTimestamps state; row presence is never confirmation. Only confirmed state may satisfy verified-finding evidence joins.';

commit;
