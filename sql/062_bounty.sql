-- 062: threat bounty network, hardened production foundation
create table bounty_researchers (
 id uuid primary key default gen_random_uuid(),
 user_id uuid unique references auth.users(id) on delete set null,
 handle text not null unique check (handle ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$'),
 display_name text check (display_name is null or length(display_name) between 1 and 120),
 country text check (country is null or country ~ '^[A-Z]{2}$'),
 tier text not null default 'bronze' check (tier in ('bronze','silver','gold','platinum')),
 vetted boolean not null default false, vetted_by uuid references auth.users(id) on delete set null, vetted_at timestamptz,
 reputation numeric(5,4) not null default 0.5000 check (reputation between 0 and 1),
 submissions_total integer not null default 0 check (submissions_total >= 0),
 accepted_total integer not null default 0 check (accepted_total >= 0), rejected_total integer not null default 0 check (rejected_total >= 0),
 paid_total_usd numeric(20,2) not null default 0 check (paid_total_usd >= 0),
 payout_method text check (payout_method in ('usdc','usdt','wire','ach','sepa','mobile_money','paypal')),
 payout_ref text, tax_country text check (tax_country is null or tax_country ~ '^[A-Z]{2}$'), tax_id text,
 status text not null default 'active' check (status in ('active','suspended','banned')), created_at timestamptz not null default now()
);
create index idx_bounty_res_status on bounty_researchers(status,tier);
create index idx_bounty_res_reputation on bounty_researchers(reputation desc);

create table bounty_campaigns (
 id uuid primary key default gen_random_uuid(), tenant_id uuid references tenants(id) on delete cascade,
 name text not null check (length(name) between 1 and 200), description text check (description is null or length(description)<=10000),
 category text not null check (category in ('ioc','rule','vulnerability','malware_sample','attribution','threat_report','tool','research')),
 acceptance jsonb not null default '{}'::jsonb, payout_tiers jsonb not null default '{}'::jsonb,
 currency text not null default 'USD' check (currency ~ '^[A-Z]{3}$'),
 budget_total numeric(20,2) not null check (budget_total>0), budget_spent numeric(20,2) not null default 0 check (budget_spent>=0 and budget_spent<=budget_total),
 starts_at timestamptz not null default now(), ends_at timestamptz, enabled boolean not null default true, created_at timestamptz not null default now(),
 check (ends_at is null or ends_at>starts_at), check (jsonb_typeof(acceptance)='object'), check (jsonb_typeof(payout_tiers)='object')
);
create index idx_bounty_camp_tenant on bounty_campaigns(tenant_id,enabled);
create index idx_bounty_camp_category on bounty_campaigns(category,enabled);
alter table bounty_campaigns enable row level security;
create policy bounty_campaigns_select on bounty_campaigns for select to authenticated using (tenant_id is null or tenant_id=(select (auth.jwt()->>'tenant_id')::uuid));

create table bounty_submissions (
 id uuid primary key default gen_random_uuid(), researcher_id uuid not null references bounty_researchers(id) on delete restrict,
 campaign_id uuid not null references bounty_campaigns(id) on delete restrict, title text not null check(length(title) between 3 and 400),
 body text not null check(length(body) between 1 and 20000), artifacts jsonb not null default '[]'::jsonb check(jsonb_typeof(artifacts)='array'),
 content_hash text not null check(content_hash ~ '^[0-9a-f]{64}$'), auto_verdict text check(auto_verdict in ('accept','reject','peer_review','curator_review')),
 auto_score numeric(6,5) check(auto_score is null or auto_score between 0 and 1), auto_reasons jsonb not null default '[]'::jsonb,
 verdict text not null default 'pending' check(verdict in ('pending','accept','reject','duplicate','malicious')),
 verdict_by uuid references auth.users(id) on delete set null, verdict_at timestamptz, verdict_reason text,
 severity text check(severity in ('low','medium','high','critical')), payout_amount numeric(20,2) check(payout_amount is null or payout_amount>=0),
 payout_status text not null default 'not_owed' check(payout_status in ('not_owed','owed','processing','paid','failed')),
 payout_tx text, payout_at timestamptz, block_ref text, created_at timestamptz not null default now(),
 unique(campaign_id,content_hash)
);
create index idx_bounty_sub_res on bounty_submissions(researcher_id,created_at desc);
create index idx_bounty_sub_camp on bounty_submissions(campaign_id,verdict,created_at desc);
create index idx_bounty_sub_payout on bounty_submissions(payout_status,created_at) where payout_status in ('owed','processing');

create table bounty_verifications (
 id bigint generated always as identity primary key, submission_id uuid not null references bounty_submissions(id) on delete cascade,
 verifier_id uuid not null references bounty_researchers(id) on delete restrict,
 role text not null check(role in ('peer','curator','adversarial')), verdict text not null check(verdict in ('accept','reject','needs_more')),
 score numeric(6,5) not null default 0.50000 check(score between 0 and 1), comment text check(comment is null or length(comment)<=5000),
 created_at timestamptz not null default now(), unique(submission_id,verifier_id,role)
);
create index idx_bounty_verif_sub on bounty_verifications(submission_id,created_at desc);

create table bounty_payouts (
 id uuid primary key default gen_random_uuid(), researcher_id uuid not null references bounty_researchers(id) on delete restrict,
 submission_id uuid unique references bounty_submissions(id) on delete set null, amount numeric(20,2) not null check(amount>0),
 currency text not null check(currency ~ '^[A-Z]{3}$'), method text not null check(method in ('usdc','usdt','wire','ach','sepa','mobile_money','paypal')),
 status text not null default 'queued' check(status in ('queued','processing','sent','confirmed','failed')),
 provider text, idempotency_key text not null unique, attempts integer not null default 0 check(attempts>=0 and attempts<=20), provider_ref text, tx_hash text, error text, created_at timestamptz not null default now(), sent_at timestamptz, confirmed_at timestamptz,
 check((status in ('sent','confirmed') and provider_ref is not null) or status not in ('sent','confirmed')),
 check(status <> 'confirmed' or confirmed_at is not null)
);
create index idx_bounty_payout_res on bounty_payouts(researcher_id,created_at desc);
create index idx_bounty_payout_status on bounty_payouts(status,created_at);

alter table bounty_researchers enable row level security;
alter table bounty_submissions enable row level security;
alter table bounty_verifications enable row level security;
alter table bounty_payouts enable row level security;
revoke all on bounty_researchers,bounty_submissions,bounty_verifications,bounty_payouts,bounty_campaigns from anon,authenticated;

create or replace function bounty_register_researcher(p_user uuid,p_handle text,p_display_name text,p_country text,payout_method text,payout_ref text)
returns uuid language plpgsql security definer set search_path=public as $$
declare v_id uuid;
begin
 if p_user is null or not exists(select 1 from auth.users where id=p_user) then raise exception 'user required'; end if;
 if p_handle is null or p_handle !~ '^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$' then raise exception 'invalid handle'; end if;
 if payout_method is not null and payout_method not in ('usdc','usdt','wire','ach','sepa','mobile_money','paypal') then raise exception 'invalid payout method'; end if;
 insert into bounty_researchers(user_id,handle,display_name,country,payout_method,payout_ref)
 values(p_user,p_handle,p_display_name,p_country,payout_method,payout_ref) returning id into v_id; return v_id;
end $$;
revoke all on function bounty_register_researcher(uuid,text,text,text,text,text) from public;
grant execute on function bounty_register_researcher(uuid,text,text,text,text,text) to service_role;

create or replace function bounty_submit(p_researcher uuid,p_campaign uuid,p_title text,p_body text,p_artifacts jsonb,p_content_hash text,p_auto_verdict text,p_auto_score real,p_auto_reasons jsonb)
returns uuid language plpgsql security definer set search_path=public as $$
declare v_id uuid; v_status text; v_enabled boolean; v_start timestamptz; v_end timestamptz;
begin
 select r.status,c.enabled,c.starts_at,c.ends_at into v_status,v_enabled,v_start,v_end from bounty_researchers r cross join bounty_campaigns c where r.id=p_researcher and c.id=p_campaign;
 if v_status is null or v_status<>'active' then raise exception 'researcher not active'; end if;
 if coalesce(v_enabled,false)=false or now()<v_start or (v_end is not null and now()>=v_end) then raise exception 'campaign not active'; end if;
 insert into bounty_submissions(researcher_id,campaign_id,title,body,artifacts,content_hash,auto_verdict,auto_score,auto_reasons)
 values(p_researcher,p_campaign,left(p_title,400),left(p_body,20000),p_artifacts,lower(p_content_hash),p_auto_verdict,p_auto_score,p_auto_reasons) returning id into v_id;
 update bounty_researchers set submissions_total=submissions_total+1 where id=p_researcher; return v_id;
exception when unique_violation then raise exception 'duplicate submission'; end $$;
revoke all on function bounty_submit(uuid,uuid,text,text,jsonb,text,text,real,jsonb) from public;
grant execute on function bounty_submit(uuid,uuid,text,text,jsonb,text,text,real,jsonb) to service_role;

create or replace function bounty_decide(p_submission uuid,p_verdict text,p_severity text,p_payout numeric,p_verdict_by uuid,p_reason text,p_block_ref text default null)
returns void language plpgsql security definer set search_path=public as $$
declare v_researcher uuid; v_campaign uuid; v_old text; v_budget numeric; v_amount numeric;
begin
 if p_verdict not in ('accept','reject','duplicate','malicious') then raise exception 'invalid verdict'; end if;
 if p_verdict='accept' and p_severity not in ('low','medium','high','critical') then raise exception 'severity required'; end if;
 if p_verdict='accept' and (p_block_ref is null or length(trim(p_block_ref))=0) then raise exception 'confirmed block reference required'; end if;
 select researcher_id,campaign_id,verdict into v_researcher,v_campaign,v_old from bounty_submissions where id=p_submission for update;
 if v_researcher is null then raise exception 'submission not found'; end if;
 if v_old<>'pending' then raise exception 'submission already decided'; end if;
 select budget_total-budget_spent into v_budget from bounty_campaigns where id=v_campaign for update;
 v_amount:=case when p_verdict='accept' then greatest(coalesce(p_payout,0),0) else 0 end;
 if v_amount>v_budget then raise exception 'campaign budget exceeded'; end if;
 update bounty_submissions set verdict=p_verdict,severity=case when p_verdict='accept' then p_severity else null end,
 payout_amount=case when p_verdict='accept' then v_amount else null end,payout_status=case when p_verdict='accept' and v_amount>0 then 'owed' else 'not_owed' end,
 verdict_by=p_verdict_by,verdict_at=now(),verdict_reason=left(p_reason,1000),block_ref=left(p_block_ref,500) where id=p_submission;
 if p_verdict='accept' then
  update bounty_campaigns set budget_spent=budget_spent+v_amount where id=v_campaign;
  update bounty_researchers set accepted_total=accepted_total+1,reputation=least(1,reputation+0.02) where id=v_researcher;
 else
  update bounty_researchers set rejected_total=rejected_total+1,reputation=greatest(0,reputation-0.03) where id=v_researcher;
 end if;
end $$;
revoke all on function bounty_decide(uuid,text,text,numeric,uuid,text,text) from public;
grant execute on function bounty_decide(uuid,text,text,numeric,uuid,text,text) to service_role;

create or replace function bounty_claim_payouts(p_limit integer default 50)
returns setof bounty_payouts language plpgsql security definer set search_path=public as $$
begin
 if p_limit<1 or p_limit>200 then raise exception 'invalid payout batch'; end if;
 return query
 with candidates as (
  select s.id from bounty_submissions s join bounty_researchers r on r.id=s.researcher_id join bounty_campaigns c on c.id=s.campaign_id where s.payout_status='owed' and s.payout_amount>0 and r.payout_method is not null and c.enabled and now() >= c.starts_at and (c.ends_at is null or now() < c.ends_at) order by s.created_at for update of s skip locked limit p_limit
 ), claimed as (
  update bounty_submissions s set payout_status='processing' from candidates c where s.id=c.id returning s.*
 )
 insert into bounty_payouts(researcher_id,submission_id,amount,currency,method,status,provider,idempotency_key,attempts)
 select s.researcher_id,s.id,s.payout_amount,c.currency,r.payout_method,'processing',null,md5('cyclothone:bounty:payout:'||s.id::text),1
 from claimed s join bounty_campaigns c on c.id=s.campaign_id join bounty_researchers r on r.id=s.researcher_id
 where r.payout_method is not null
 on conflict(submission_id) do update set status='processing',attempts=bounty_payouts.attempts+1,error=null,provider_ref=null,tx_hash=null,sent_at=null,confirmed_at=null
 where bounty_payouts.status in ('queued','failed') and bounty_payouts.attempts < 20
 returning *;
end $$;
revoke all on function bounty_claim_payouts(integer) from public;
grant execute on function bounty_claim_payouts(integer) to service_role;

create or replace function bounty_requeue_failed(p_payout uuid)
returns void language plpgsql security definer set search_path=public as $
declare v_submission uuid; v_status text; v_attempts integer;
begin
 select submission_id,status,attempts into v_submission,v_status,v_attempts from bounty_payouts where id=p_payout for update;
 if v_submission is null then raise exception 'payout not found'; end if;
 if v_status<>'failed' then raise exception 'only failed payouts can be requeued'; end if;
 if v_attempts>=20 then raise exception 'payout retry limit reached'; end if;
 update bounty_payouts set status='queued',error=null where id=p_payout;
 update bounty_submissions set payout_status='owed' where id=v_submission and payout_status='failed';
end $;
revoke all on function bounty_requeue_failed(uuid) from public;
grant execute on function bounty_requeue_failed(uuid) to service_role;

create or replace function bounty_mark_payout(p_payout uuid,p_status text,p_provider_ref text default null,p_tx_hash text default null,p_error text default null)
returns void language plpgsql security definer set search_path=public as $$
declare v_submission uuid; v_researcher uuid; v_amount numeric;
begin
 if p_status not in ('sent','confirmed','failed') then raise exception 'invalid payout transition'; end if;
 select submission_id,researcher_id,amount into v_submission,v_researcher,v_amount from bounty_payouts where id=p_payout for update;
 if v_submission is null then raise exception 'payout not found'; end if;
 if p_status in ('sent','confirmed') and coalesce(p_provider_ref,p_tx_hash) is null then raise exception 'provider reference required'; end if;
 if (select status from bounty_payouts where id=p_payout)='confirmed' then raise exception 'payout already confirmed'; end if;
 if (select status from bounty_payouts where id=p_payout)='failed' then raise exception 'failed payout requires requeue'; end if;
 if (select status from bounty_payouts where id=p_payout)='sent' and p_status not in ('confirmed','sent') then raise exception 'invalid payout transition'; end if;
 update bounty_payouts set status=p_status,provider_ref=coalesce(p_provider_ref,provider_ref),tx_hash=coalesce(p_tx_hash,tx_hash),
 error=case when p_status='failed' then left(p_error,500) else null end,sent_at=case when p_status in ('sent','confirmed') then coalesce(sent_at,now()) else sent_at end,
 confirmed_at=case when p_status='confirmed' then coalesce(confirmed_at,now()) else confirmed_at end where id=p_payout;
 if p_status='confirmed' then
  update bounty_submissions set payout_status='paid',payout_tx=coalesce(p_tx_hash,p_provider_ref),payout_at=coalesce(payout_at,now()) where id=v_submission and payout_status='processing';
  update bounty_researchers set paid_total_usd=paid_total_usd+v_amount where id=v_researcher;
 elsif p_status='failed' then update bounty_submissions set payout_status='failed' where id=v_submission and payout_status='processing'; end if;
end $$;
revoke all on function bounty_mark_payout(uuid,text,text,text,text) from public;
grant execute on function bounty_mark_payout(uuid,text,text,text,text) to service_role;

create or replace function bounty_stats(p_tenant uuid) returns jsonb language sql stable security definer set search_path=public as $$
select jsonb_build_object(
'researchers_total',(select count(*) from bounty_researchers where status='active'),
'researchers_vetted',(select count(*) from bounty_researchers where status='active' and vetted),
'campaigns_active',(select count(*) from bounty_campaigns where enabled and (tenant_id is null or tenant_id=p_tenant)),
'submissions_30d',(select count(*) from bounty_submissions s join bounty_campaigns c on c.id=s.campaign_id where s.created_at>now()-interval '30 days' and (c.tenant_id is null or c.tenant_id=p_tenant)),
'accepted_30d',(select count(*) from bounty_submissions s join bounty_campaigns c on c.id=s.campaign_id where s.verdict='accept' and s.created_at>now()-interval '30 days' and (c.tenant_id is null or c.tenant_id=p_tenant)),
'paid_total',(select coalesce(sum(p.amount),0) from bounty_payouts p join bounty_submissions s on s.id=p.submission_id join bounty_campaigns c on c.id=s.campaign_id where p.status in ('sent','confirmed') and (c.tenant_id is null or c.tenant_id=p_tenant)),
'owed_total',(select coalesce(sum(s.payout_amount),0) from bounty_submissions s join bounty_campaigns c on c.id=s.campaign_id where s.payout_status in ('owed','processing') and (c.tenant_id is null or c.tenant_id=p_tenant)));
$$;
revoke all on function bounty_stats(uuid) from public;
grant execute on function bounty_stats(uuid) to service_role;
