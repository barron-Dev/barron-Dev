-- Sentinel Compliance hardening, migration 026.
-- Evidence is append-only; generated packs carry a signed manifest and a separate
-- immutable ZIP digest. Tenant ownership remains enforced by RLS.

alter table public.compliance_evidence
    add column if not exists collected_at timestamptz not null default now(),
    add column if not exists provenance jsonb not null default '{}'::jsonb;

alter table public.compliance_evidence_snapshots
    add column if not exists manifest_sha256 text,
    add column if not exists evidence_count integer not null default 0,
    add column if not exists verification_status text not null default 'unverified'
        check (verification_status in ('unverified','verified','failed'));

create index if not exists compliance_evidence_tenant_collected_idx
    on public.compliance_evidence (tenant_id, collected_at desc);

create index if not exists compliance_snapshots_manifest_idx
    on public.compliance_evidence_snapshots (tenant_id, manifest_sha256)
    where manifest_sha256 is not null;

create or replace function public.compliance_immutable_guard()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
    if current_user <> 'service_role' then
        raise exception 'compliance evidence is append-only';
    end if;
    if tg_op = 'DELETE' then
        raise exception 'compliance evidence cannot be deleted';
    end if;
    if tg_op = 'UPDATE' then
        raise exception 'compliance evidence cannot be updated';
    end if;
    return new;
end;
$$;

drop trigger if exists compliance_evidence_immutable on public.compliance_evidence;
create trigger compliance_evidence_immutable
before update or delete on public.compliance_evidence
for each row execute function public.compliance_immutable_guard();

drop trigger if exists compliance_attestations_immutable on public.compliance_attestations;
create trigger compliance_attestations_immutable
before update or delete on public.compliance_attestations
for each row execute function public.compliance_immutable_guard();

drop trigger if exists compliance_snapshots_immutable on public.compliance_evidence_snapshots;
create trigger compliance_snapshots_immutable
before update or delete on public.compliance_evidence_snapshots
for each row execute function public.compliance_immutable_guard();

create table if not exists public.compliance_collection_results (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    run_id uuid references public.compliance_runs(id) on delete set null,
    framework text not null,
    control_id uuid references public.compliance_controls(id) on delete set null,
    source_ref text not null,
    status text not null check (status in ('collected','empty','failed','stale')),
    row_count integer not null default 0 check (row_count >= 0),
    error_code text,
    error_detail text,
    collected_at timestamptz not null default now(),
    valid_until timestamptz,
    provenance jsonb not null default '{}'::jsonb
);

create index if not exists compliance_collection_results_tenant_idx
    on public.compliance_collection_results (tenant_id, collected_at desc);

alter table public.compliance_collection_results enable row level security;
create policy compliance_collection_results_tenant
on public.compliance_collection_results
using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

create or replace function public.verify_compliance_snapshot(
    p_tenant_id uuid,
    p_snapshot_id uuid,
    p_pack_sha256 text,
    p_manifest_sha256 text
)
returns boolean
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
    v_pack text;
    v_manifest text;
begin
    select pack_sha256, manifest_sha256
      into v_pack, v_manifest
      from public.compliance_evidence_snapshots
     where id = p_snapshot_id and tenant_id = p_tenant_id;
    if v_pack is null or v_manifest is null then
        return false;
    end if;
    return v_pack = p_pack_sha256 and v_manifest = p_manifest_sha256;
end;
$$;

revoke all on function public.verify_compliance_snapshot(uuid, uuid, text, text)
from public, anon, authenticated;
grant execute on function public.verify_compliance_snapshot(uuid, uuid, text, text)
to service_role;
