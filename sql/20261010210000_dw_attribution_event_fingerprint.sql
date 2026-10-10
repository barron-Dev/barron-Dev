-- Allow a new alert only when assessment evidence/tier materially changes; repeated
-- processing of the same cluster remains idempotent.
alter table public.dw_attribution_alert_outbox
  add column if not exists event_fingerprint text not null default '';
drop index if exists public.dw_attribution_alert_outbox_assessment_event_uidx;
drop index if exists public.dw_attribution_alert_assessment_event_uidx;
create unique index if not exists dw_attribution_alert_event_fingerprint_uidx
  on public.dw_attribution_alert_outbox(tenant_id, assessment_id, event_type, event_fingerprint);
