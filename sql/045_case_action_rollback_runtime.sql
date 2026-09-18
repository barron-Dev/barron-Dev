-- Runtime alignment for rollback state used by the unified response layer.
alter table public.case_actions
    add column if not exists rollback_command_id uuid references public.commands(id) on delete set null,
    add column if not exists rolled_back_at timestamptz,
    add column if not exists rollback_error text;

create index if not exists idx_case_actions_rollback_command
    on public.case_actions(rollback_command_id);
