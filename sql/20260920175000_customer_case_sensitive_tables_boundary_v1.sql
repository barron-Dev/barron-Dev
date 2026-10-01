-- Customer-facing APIs must use vetted RPCs, not direct access to internal case data.
revoke all on table public.case_actions from anon, authenticated;
revoke all on table public.case_timeline from anon, authenticated;
revoke all on table public.crime_cases from anon, authenticated;
revoke all on table public.customer_case_activity from anon, authenticated;
revoke all on table public.customer_case_assignments from anon, authenticated;
