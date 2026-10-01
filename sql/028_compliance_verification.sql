-- Sentinel Compliance verification records.
-- Snapshots remain immutable; each verification attempt is append-only evidence.

create table if not exists public.compliance_snapshot_verifications (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references public.tenants(id) on delete cascade,
    snapshot_id uuid not null references public.compliance_evidence_snapshots(id) on delete cascade,
    verified boolean not null,
    pack_sha256 text not null,
    manifest_sha256 text not null,
    checks jsonb not null default '{}'::jsonb,
    verified_at timestamptz not null default now()
);

create index if not exists compliance_snapshot_verifications_tenant_idx
    on public.compliance_snapshot_verifications (tenant_id, verified_at desc);

create index if not exists compliance_snapshot_verifications_snapshot_idx
    on public.compliance_snapshot_verifications (snapshot_id, verified_at desc);

alter table public.compliance_snapshot_verifications enable row level security;

drop policy if exists compliance_snapshot_verifications_tenant on public.compliance_snapshot_verifications;
create policy compliance_snapshot_verifications_tenant
on public.compliance_snapshot_verifications
for select
to authenticated
using (tenant_id = (auth.jwt() ->> 'tenant_id')::uuid);

-- Verification records are append-only from the API perspective.
create or replace function public.compliance_snapshot_verification_immutable_guard()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
begin
    raise exception 'compliance verification records are append-only';
end;
$$;

drop trigger if exists compliance_snapshot_verification_immutable on public.compliance_snapshot_verifications;
create trigger compliance_snapshot_verification_immutable
before update or delete on public.compliance_snapshot_verifications
for each row execute function public.compliance_snapshot_verification_immutable_guard();

revoke all on function public.compliance_snapshot_verification_immutable_guard() from public, anon, authenticated;
grant execute on function public.compliance_snapshot_verification_immutable_guard() to service_role;

-- Only the backend service may write verification records.
revoke insert, update, delete on public.compliance_snapshot_verifications from authenticated, anon;
grant insert on public.compliance_snapshot_verifications to service_role;
