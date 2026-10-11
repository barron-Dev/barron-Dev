-- HIBP is intentionally excluded from Cyclothone's active source set.
-- Keep the legacy row for auditability, but prevent it from being advertised as active.
begin;
update public.dw_sources
set enabled = false,
    last_status = 'excluded_by_policy'
where id = 'hibp';
commit;
