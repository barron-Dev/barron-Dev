-- Cyclothone Security State; additive migration.
-- Applied to Supabase project whcomikcftbousoqzeal; see release notes for verification.
begin;
create table if not exists public.security_targets (
 id uuid primary key default gen_random_uuid(), organization_id uuid not null,
 target_key text not null, target_kind text not null default 'domain',
 display_name text, metadata jsonb not null default '{}'::jsonb,
 created_at timestamptz not null default now(), updated_at timestamptz not null default now(),
 unique (organization_id,target_key)
);
create table if not exists public.security_claims (
 id uuid primary key default gen_random_uuid(), organization_id uuid not null,
 target_id uuid not null references public.security_targets(id) on delete cascade,
 target_key text not null,
 claim_type text not null check (claim_type in ('dark_web_exposure','public_surface_assessment')),
 status text not null default 'active' check (status in ('active','superseded','withdrawn')),
 coverage_status text not null default 'partial' check (coverage_status in ('verified_partial','partial','attention','blocked')),
 severity text not null default 'unknown' check (severity in ('info','low','medium','high','critical','unknown')),
 title text not null, statement text not null,
 confidence numeric(5,4) check (confidence is null or confidence between 0 and 1),
 sources_checked integer not null default 0 check (sources_checked >= 0),
 sources_unavailable integer not null default 0 check (sources_unavailable >= 0),
 finding_count integer not null default 0 check (finding_count >= 0),
 high_finding_count integer not null default 0 check (high_finding_count >= 0),
 evidence jsonb not null default '{}'::jsonb, origin_service_key text, origin_request_id uuid,
 version integer not null default 1 check (version >= 1),
 observed_at timestamptz not null default now(), created_at timestamptz not null default now(),
 updated_at timestamptz not null default now(),
 unique (organization_id,target_key,claim_type)
);
create index if not exists idx_security_targets_org on public.security_targets(organization_id,updated_at desc);
create index if not exists idx_security_claims_org_updated on public.security_claims(organization_id,updated_at desc);
create index if not exists idx_security_claims_target on public.security_claims(target_id,claim_type);
create index if not exists idx_security_claims_request on public.security_claims(origin_request_id);
create table if not exists public.security_claim_history (
 id uuid primary key default gen_random_uuid(),
 claim_id uuid not null references public.security_claims(id) on delete cascade,
 organization_id uuid not null, version integer not null, coverage_status text not null,
 severity text not null, title text not null, statement text not null,
 evidence jsonb not null default '{}'::jsonb, origin_request_id uuid,
 observed_at timestamptz not null, recorded_at timestamptz not null default now(),
 unique (claim_id,version)
);
create index if not exists idx_security_claim_history_version on public.security_claim_history(claim_id,version desc);
create table if not exists public.security_claim_requests (
 claim_id uuid not null references public.security_claims(id) on delete cascade,
 service_request_id uuid not null, role text not null default 'origin' check (role in ('origin','refresh')),
 created_at timestamptz not null default now(), primary key (claim_id,service_request_id)
);
alter table public.security_targets enable row level security;
alter table public.security_claims enable row level security;
alter table public.security_claim_history enable row level security;
alter table public.security_claim_requests enable row level security;
create schema if not exists private;
create or replace function private.security_is_org_member(p_org_id uuid)
returns boolean language sql stable security definer set search_path = pg_catalog, public
as $function$
 select exists(select 1 from public.organization_members m
  where m.organization_id=p_org_id and m.user_id=auth.uid() and m.status='active');
$function$;
revoke all on function private.security_is_org_member(uuid) from public,anon;
grant execute on function private.security_is_org_member(uuid) to authenticated,service_role;
drop policy if exists security_targets_select on public.security_targets;
create policy security_targets_select on public.security_targets for select to authenticated
 using(private.security_is_org_member(organization_id));
drop policy if exists security_targets_insert on public.security_targets;
create policy security_targets_insert on public.security_targets for insert to authenticated
 with check(private.security_is_org_member(organization_id));
drop policy if exists security_targets_update on public.security_targets;
create policy security_targets_update on public.security_targets for update to authenticated
 using(private.security_is_org_member(organization_id))
 with check(private.security_is_org_member(organization_id));
drop policy if exists security_claims_select on public.security_claims;
create policy security_claims_select on public.security_claims for select to authenticated
 using(private.security_is_org_member(organization_id));
drop policy if exists security_claim_history_select on public.security_claim_history;
create policy security_claim_history_select on public.security_claim_history for select to authenticated
 using(private.security_is_org_member(organization_id));
drop policy if exists security_claim_requests_select on public.security_claim_requests;
create policy security_claim_requests_select on public.security_claim_requests for select to authenticated
 using(exists(select 1 from public.security_claims c where c.id=claim_id and private.security_is_org_member(c.organization_id)));
grant select,insert,update on public.security_targets to authenticated;
grant select on public.security_claims,public.security_claim_history,public.security_claim_requests to authenticated;
grant all on public.security_targets,public.security_claims,public.security_claim_history,public.security_claim_requests to service_role;
create or replace function public.upsert_security_claim(
 p_organization_id uuid,p_target_key text,p_target_kind text,p_claim_type text,
 p_coverage_status text,p_severity text,p_title text,p_statement text,p_confidence numeric,
 p_sources_checked integer,p_sources_unavailable integer,p_finding_count integer,
 p_high_finding_count integer,p_evidence jsonb,p_origin_service_key text,
 p_origin_request_id uuid,p_observed_at timestamptz default now()
) returns public.security_claims language plpgsql security definer
set search_path = pg_catalog, public as $function$
declare v_target_id uuid; v_old public.security_claims%rowtype; v_new public.security_claims%rowtype; v_key text;
begin
 if p_organization_id is null or nullif(trim(p_target_key),'') is null then raise exception 'organization and target required'; end if;
 if p_claim_type not in ('dark_web_exposure','public_surface_assessment') then raise exception 'invalid claim type'; end if;
 if p_coverage_status not in ('verified_partial','partial','attention','blocked') then raise exception 'invalid coverage'; end if;
 if p_severity not in ('info','low','medium','high','critical','unknown') then raise exception 'invalid severity'; end if;
 if coalesce(p_sources_checked,0)<0 or coalesce(p_sources_unavailable,0)<0 or coalesce(p_finding_count,0)<0 or coalesce(p_high_finding_count,0)<0 then raise exception 'negative counts'; end if;
 v_key:=lower(trim(p_target_key)); if length(v_key)>255 then raise exception 'target too long'; end if;
 insert into public.security_targets(organization_id,target_key,target_kind,display_name)
 values(p_organization_id,v_key,coalesce(nullif(p_target_kind,''),'domain'),v_key)
 on conflict(organization_id,target_key) do update set updated_at=now() returning id into v_target_id;
 select * into v_old from public.security_claims where organization_id=p_organization_id and target_key=v_key and claim_type=p_claim_type for update;
 if found then
  insert into public.security_claim_history(claim_id,organization_id,version,coverage_status,severity,title,statement,evidence,origin_request_id,observed_at)
  values(v_old.id,v_old.organization_id,v_old.version,v_old.coverage_status,v_old.severity,v_old.title,v_old.statement,v_old.evidence,v_old.origin_request_id,v_old.observed_at)
  on conflict(claim_id,version) do nothing;
  update public.security_claims set target_id=v_target_id,coverage_status=p_coverage_status,severity=p_severity,
   title=p_title,statement=p_statement,confidence=p_confidence,sources_checked=coalesce(p_sources_checked,0),
   sources_unavailable=coalesce(p_sources_unavailable,0),finding_count=coalesce(p_finding_count,0),
   high_finding_count=coalesce(p_high_finding_count,0),evidence=coalesce(p_evidence,'{}'::jsonb),
   origin_service_key=p_origin_service_key,origin_request_id=p_origin_request_id,version=v_old.version+1,
   observed_at=coalesce(p_observed_at,now()),updated_at=now(),status='active'
  where id=v_old.id returning * into v_new;
 else
  insert into public.security_claims(organization_id,target_id,target_key,claim_type,coverage_status,severity,title,statement,confidence,sources_checked,sources_unavailable,finding_count,high_finding_count,evidence,origin_service_key,origin_request_id,observed_at)
  values(p_organization_id,v_target_id,v_key,p_claim_type,p_coverage_status,p_severity,p_title,p_statement,p_confidence,
   coalesce(p_sources_checked,0),coalesce(p_sources_unavailable,0),coalesce(p_finding_count,0),coalesce(p_high_finding_count,0),
   coalesce(p_evidence,'{}'::jsonb),p_origin_service_key,p_origin_request_id,coalesce(p_observed_at,now())) returning * into v_new;
 end if;
 if p_origin_request_id is not null then
  insert into public.security_claim_requests(claim_id,service_request_id,role)
  values(v_new.id,p_origin_request_id,case when v_old.id is null then 'origin' else 'refresh' end) on conflict do nothing;
 end if;
 return v_new;
end;
$function$;
revoke all on function public.upsert_security_claim(uuid,text,text,text,text,text,text,text,numeric,integer,integer,integer,integer,jsonb,text,uuid,timestamptz) from public,anon,authenticated;
grant execute on function public.upsert_security_claim(uuid,text,text,text,text,text,text,text,numeric,integer,integer,integer,integer,jsonb,text,uuid,timestamptz) to service_role;
comment on table public.security_claims is 'Claims derived by trusted backend code from real terminal service executions.';
commit;
