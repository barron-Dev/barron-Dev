-- Cyclothone DW probabilistic attribution and threat-actor profiles.
-- Global actor intelligence is written only by service_role; customer access must
-- go through tenant-authorized API routes. This migration is NOT applied by commit.

create table if not exists public.dw_actor_profiles (
  actor_id text primary key check (length(actor_id) between 3 and 128),
  primary_name text not null check (length(primary_name) between 1 and 200),
  actor_type text not null default 'UNKNOWN' check (actor_type in ('STATE_SPONSORED','FINANCIALLY_MOTIVATED','HACKTIVIST','CYBERCRIMINAL','HACKER_FOR_HIRE','UNKNOWN')),
  aliases jsonb not null default '[]'::jsonb,
  attributed_to text,
  attribution_confidence text not null default 'INSUFFICIENT' check (attribution_confidence in ('CONFIRMED','SUSPECTED','POSSIBLE','INSUFFICIENT')),
  profile jsonb not null default '{}'::jsonb,
  first_seen timestamptz,
  last_activity timestamptz,
  source_count integer not null default 0 check (source_count >= 0),
  analyst_review_required boolean not null default true,
  provisional boolean not null default true,
  profile_version integer not null default 1 check (profile_version > 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists dw_actor_profiles_type_idx on public.dw_actor_profiles(actor_type);
create index if not exists dw_actor_profiles_activity_idx on public.dw_actor_profiles(last_activity desc);
alter table public.dw_actor_profiles enable row level security;

create table if not exists public.dw_attribution_assessments (
  assessment_id uuid primary key default gen_random_uuid(),
  activity_cluster_id text not null,
  actor_id text references public.dw_actor_profiles(actor_id) on delete set null,
  score numeric(4,3) not null check (score >= 0 and score <= 1),
  tier text not null check (tier in ('CONFIRMED','SUSPECTED','POSSIBLE','INSUFFICIENT')),
  raw_score_tier text not null check (raw_score_tier in ('CONFIRMED','SUSPECTED','POSSIBLE','INSUFFICIENT')),
  signals jsonb not null default '{}'::jsonb,
  explanation jsonb not null default '[]'::jsonb,
  diamond_model jsonb not null default '{}'::jsonb,
  attack_techniques jsonb not null default '[]'::jsonb,
  kill_chain_phases jsonb not null default '[]'::jsonb,
  source_evidence_ids jsonb not null default '[]'::jsonb,
  independent_source_count integer not null default 0,
  analyst_review_required boolean not null default true,
  created_at timestamptz not null default now()
);
create index if not exists dw_attribution_cluster_idx on public.dw_attribution_assessments(activity_cluster_id, created_at desc);
create index if not exists dw_attribution_actor_idx on public.dw_attribution_assessments(actor_id, created_at desc);
alter table public.dw_attribution_assessments enable row level security;

create table if not exists public.dw_actor_relationships (
  relationship_id uuid primary key default gen_random_uuid(),
  source_actor_id text not null references public.dw_actor_profiles(actor_id) on delete cascade,
  target_actor_id text not null references public.dw_actor_profiles(actor_id) on delete cascade,
  relationship_type text not null check (relationship_type in ('AFFILIATED_WITH','SUSPECTED_SPLINTER_OF','SHARES_INFRASTRUCTURE_WITH','SHARES_TTP_WITH','REBRANDED_AS','POSSIBLE_ASSOCIATION')),
  confidence numeric(4,3) not null check (confidence >= 0 and confidence <= 1),
  evidence_ids jsonb not null default '[]'::jsonb,
  analyst_review_required boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(source_actor_id, target_actor_id, relationship_type),
  check (source_actor_id <> target_actor_id)
);
create index if not exists dw_actor_relationships_source_idx on public.dw_actor_relationships(source_actor_id);
create index if not exists dw_actor_relationships_target_idx on public.dw_actor_relationships(target_actor_id);
alter table public.dw_actor_relationships enable row level security;

create table if not exists public.dw_actor_evidence (
  evidence_id uuid primary key default gen_random_uuid(),
  actor_id text references public.dw_actor_profiles(actor_id) on delete set null,
  activity_cluster_id text not null,
  evidence_type text not null check (evidence_type in ('INFRASTRUCTURE','TTP','MALWARE','BEHAVIOUR','VICTIMOLOGY','IDENTITY','TEMPORAL','SOURCE_REPORT')),
  evidence_hash text not null check (evidence_hash ~ '^[a-f0-9]{64}$'),
  source_name text not null,
  source_url text,
  observed_at timestamptz,
  confidence numeric(4,3) not null default 0.5 check (confidence >= 0 and confidence <= 1),
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  unique(activity_cluster_id, evidence_hash, evidence_type)
);
create index if not exists dw_actor_evidence_actor_idx on public.dw_actor_evidence(actor_id, observed_at desc);
create index if not exists dw_actor_evidence_cluster_idx on public.dw_actor_evidence(activity_cluster_id);
alter table public.dw_actor_evidence enable row level security;

-- No direct browser/client access to global threat intelligence tables.
revoke all on public.dw_actor_profiles, public.dw_attribution_assessments, public.dw_actor_relationships, public.dw_actor_evidence from anon, authenticated;
grant select, insert, update, delete on public.dw_actor_profiles, public.dw_attribution_assessments, public.dw_actor_relationships, public.dw_actor_evidence to service_role;
