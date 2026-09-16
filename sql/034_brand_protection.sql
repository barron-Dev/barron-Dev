-- Brand Protection foundation: tenant isolation, lifecycle hardening, and idempotent threat recording.
-- Service-role only for ingestion/mutation; customer reads remain tenant-scoped through RLS.

alter table if exists brands enable row level security;
alter table if exists brand_threats enable row level security;
alter table if exists takedown_templates enable row level security;

revoke all on table brands from anon;
revoke all on table brand_threats from anon;
revoke all on table takedown_templates from anon;

-- Never permit a client to mutate security telemetry directly.
revoke insert, update, delete on table brand_threats from authenticated;
revoke insert, update, delete on table brand_threats from service_role;

-- Revoke broad execution before explicitly granting the ingestion RPC.
revoke all on function record_brand_threat(uuid, uuid, text, text, text, text, real, text, jsonb) from public;
revoke all on function record_brand_threat(uuid, uuid, text, text, text, text, real, text, jsonb) from anon;
revoke all on function record_brand_threat(uuid, uuid, text, text, text, text, real, text, jsonb) from authenticated;
grant execute on function record_brand_threat(uuid, uuid, text, text, text, text, real, text, jsonb) to service_role;

-- Replace the ingestion RPC with explicit tenant/brand binding and bounded inputs.
create or replace function record_brand_threat(
    p_tenant uuid, p_brand uuid, p_kind text, p_identifier text,
    p_url text, p_platform text, p_similarity real,
    p_severity text, p_metadata jsonb
)
returns uuid
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_id uuid;
    v_brand_tenant uuid;
begin
    if p_tenant is null or p_brand is null then
        raise exception 'tenant and brand are required';
    end if;

    select tenant_id into v_brand_tenant
      from brands
     where id = p_brand;

    if v_brand_tenant is null or v_brand_tenant <> p_tenant then
        raise exception 'brand does not belong to tenant';
    end if;

    if p_kind not in (
        'typosquat','homoglyph','combosquat','tld_swap','subdomain_trick',
        'social_handle','fake_app','fake_listing','phishing_page',
        'trademark_abuse','lookalike_logo','fake_recruitment','fake_support'
    ) then
        raise exception 'invalid brand threat kind';
    end if;

    if p_severity not in ('low','medium','high','critical') then
        raise exception 'invalid severity';
    end if;

    if p_similarity is null or p_similarity < 0 or p_similarity > 1 then
        raise exception 'similarity must be between 0 and 1';
    end if;

    if length(trim(coalesce(p_identifier, ''))) = 0 or length(p_identifier) > 2048 then
        raise exception 'invalid identifier';
    end if;

    insert into brand_threats (
        tenant_id, brand_id, kind, identifier, url, platform,
        similarity, severity, metadata
    ) values (
        p_tenant, p_brand, p_kind, trim(p_identifier), p_url, p_platform,
        p_similarity, p_severity, coalesce(p_metadata, '{}'::jsonb)
    )
    on conflict (tenant_id, kind, identifier) do update
       set brand_id = excluded.brand_id,
           url = coalesce(excluded.url, brand_threats.url),
           platform = coalesce(excluded.platform, brand_threats.platform),
           last_seen = now(),
           similarity = greatest(excluded.similarity, brand_threats.similarity),
           severity = case
             when brand_threats.severity = 'critical' or excluded.severity = 'critical' then 'critical'
             when brand_threats.severity = 'high' or excluded.severity = 'high' then 'high'
             when brand_threats.severity = 'medium' or excluded.severity = 'medium' then 'medium'
             else 'low'
           end,
           metadata = brand_threats.metadata || excluded.metadata
    returning id into v_id;

    return v_id;
end;
$$;

-- Threat identifiers are tenant-scoped; no cross-tenant inference is permitted.
create index if not exists idx_brand_threats_tenant_kind_identifier
    on brand_threats(tenant_id, kind, identifier);

create index if not exists idx_brands_tenant_domain
    on brands(tenant_id, primary_domain);
