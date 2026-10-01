-- Align playbook runs with the case-driven response lifecycle.
alter table public.playbook_runs
    add column if not exists case_id uuid references public.crime_cases(id) on delete set null;

create index if not exists idx_playbook_runs_case
    on public.playbook_runs(tenant_id, case_id, started_at desc);
