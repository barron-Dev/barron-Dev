-- Security boundary: keep pg_trgm extension objects out of the exposed public schema.
-- No trigram indexes or application functions currently depend on pg_trgm in public.
alter extension pg_trgm set schema extensions;
