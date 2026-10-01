-- Legacy authorization reconciliation: replace JWT tenant claims with membership-derived tenant isolation.
-- Commands and case_actions remain client-authenticated only; anon has no table privileges.
drop policy if exists commands_tenant on public.commands;
create policy commands_tenant on public.commands
  for all to authenticated
  using (exists (select 1 from public.tenant_members tm where tm.tenant_id = commands.tenant_id and tm.user_id = (select auth.uid())))
  with check (exists (select 1 from public.tenant_members tm where tm.tenant_id = commands.tenant_id and tm.user_id = (select auth.uid())));
revoke all on table public.commands from anon;

drop policy if exists case_actions_tenant on public.case_actions;
create policy case_actions_tenant on public.case_actions
  for all to authenticated
  using (exists (select 1 from public.tenant_members tm where tm.tenant_id = case_actions.tenant_id and tm.user_id = (select auth.uid())))
  with check (exists (select 1 from public.tenant_members tm where tm.tenant_id = case_actions.tenant_id and tm.user_id = (select auth.uid())));
revoke all on table public.case_actions from anon;
