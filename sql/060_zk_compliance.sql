-- 060: zero-knowledge compliance foundation
create table zk_policies (
 id uuid primary key default gen_random_uuid(),
 tenant_id uuid not null references tenants(id) on delete cascade,
 name text not null check (length(name) between 1 and 120),
 predicate_kind text not null check (predicate_kind in ('count_gte','sum_gte','sum_lte','exists','rate_gte','coverage_gte')),
 predicate jsonb not null,
 regulator text,
 valid_from timestamptz,
 valid_until timestamptz,
 enabled boolean not null default true,
 created_at timestamptz not null default now(),
 check (valid_until is null or valid_from is null or valid_until > valid_from)
);
create index idx_zk_policy_tenant on zk_policies(tenant_id,enabled);
alter table zk_policies enable row level security;
create policy zk_policies_select on zk_policies for select to authenticated
 using (tenant_id=(select (auth.jwt()->>'tenant_id')::uuid));

create table zk_commitments (
 id uuid primary key default gen_random_uuid(),
 tenant_id uuid not null references tenants(id) on delete cascade,
 policy_id uuid references zk_policies(id) on delete set null,
 period_start timestamptz not null,
 period_end timestamptz not null,
 metric text not null check (length(metric) between 1 and 120),
 bucket bigint not null,
 commitment text not null check (commitment ~ '^[0-9a-f]{64}$'),
 blinding_ref text not null,
 leaf_index integer not null check (leaf_index >= 0),
 merkle_root text not null check (merkle_root ~ '^[0-9a-f]{64}$'),
 created_at timestamptz not null default now(),
 unique(tenant_id,policy_id,metric,period_start,leaf_index),
 check(period_end>period_start)
);
create index idx_zk_commit_tenant on zk_commitments(tenant_id,period_start desc);
create index idx_zk_commit_root on zk_commitments(merkle_root);
alter table zk_commitments enable row level security;
create policy zk_commitments_select on zk_commitments for select to authenticated
 using (tenant_id=(select (auth.jwt()->>'tenant_id')::uuid));

create table zk_proofs (
 id uuid primary key default gen_random_uuid(),
 tenant_id uuid not null references tenants(id) on delete cascade,
 policy_id uuid not null references zk_policies(id) on delete cascade,
 statement jsonb not null,
 merkle_root text not null check (merkle_root ~ '^[0-9a-f]{64}$'),
 proof_system text not null check (proof_system in ('merkle_commitment_v1')),
 proof_version text not null default '1',
 proof_payload jsonb not null,
 signature text not null,
 signer_kid text not null,
 status text not null default 'issued' check(status in ('issued','verified','rejected','expired')),
 verified_at timestamptz,
 verifier_id uuid references auth.users(id) on delete set null,
 verifier_note text,
 share_token text unique,
 share_expires timestamptz,
 created_at timestamptz not null default now()
);
create index idx_zk_proof_tenant on zk_proofs(tenant_id,created_at desc);
alter table zk_proofs enable row level security;
create policy zk_proofs_select on zk_proofs for select to authenticated
 using (tenant_id=(select (auth.jwt()->>'tenant_id')::uuid));

create table zk_verifications (
 id bigint generated always as identity primary key,
 proof_id uuid not null references zk_proofs(id) on delete cascade,
 verifier_ip inet,
 verifier_ua text,
 result boolean not null,
 reason text,
 verified_at timestamptz not null default now()
);
create index idx_zk_verify_proof on zk_verifications(proof_id,verified_at desc);
alter table zk_verifications enable row level security;
revoke all on zk_verifications from anon,authenticated;

revoke all on zk_policies,zk_commitments,zk_proofs from anon,authenticated;
grant select on zk_policies,zk_commitments,zk_proofs to authenticated;

create or replace function zk_record_commitment(
 p_tenant uuid,p_policy uuid,p_metric text,p_bucket bigint,p_commitment text,
 p_blinding_ref text,p_leaf_index integer,p_merkle_root text,
 p_period_start timestamptz,p_period_end timestamptz
) returns uuid language plpgsql security definer set search_path=public
as $$
declare v_id uuid;
begin
 if p_tenant is null or p_policy is null or p_leaf_index < 0 then raise exception 'invalid commitment'; end if;
 if not exists(select 1 from zk_policies where id=p_policy and tenant_id=p_tenant) then raise exception 'policy tenant mismatch'; end if;
 insert into zk_commitments(tenant_id,policy_id,metric,bucket,commitment,blinding_ref,leaf_index,merkle_root,period_start,period_end)
 values(p_tenant,p_policy,p_metric,p_bucket,lower(p_commitment),p_blinding_ref,p_leaf_index,lower(p_merkle_root),p_period_start,p_period_end)
 returning id into v_id;
 return v_id;
end $$;
revoke all on function zk_record_commitment(uuid,uuid,text,bigint,text,text,integer,text,timestamptz,timestamptz) from public;
grant execute on function zk_record_commitment(uuid,uuid,text,bigint,text,text,integer,text,timestamptz,timestamptz) to service_role;

create or replace function zk_stats(p_tenant uuid) returns jsonb language sql stable security definer set search_path=public
as $$
 select jsonb_build_object(
 'policies',(select count(*) from zk_policies where tenant_id=p_tenant and enabled),
 'commitments',(select count(*) from zk_commitments where tenant_id=p_tenant),
 'proofs',(select count(*) from zk_proofs where tenant_id=p_tenant),
 'verified',(select count(*) from zk_proofs where tenant_id=p_tenant and status='verified'),
 'rejected',(select count(*) from zk_proofs where tenant_id=p_tenant and status='rejected'));
$$;
revoke all on function zk_stats(uuid) from public;
grant execute on function zk_stats(uuid) to service_role;
