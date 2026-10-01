begin;
do $$
declare
  r record;
  v_sql text;
begin
  for r in
    select p.oid
    from pg_proc p
    join pg_namespace n on n.oid=p.pronamespace
    where n.nspname='public'
      and p.prosecdef
      and p.prosrc like '%current_user%'
      and p.prosrc like '%service_role%'
  loop
    v_sql := regexp_replace(
      pg_get_functiondef(r.oid),
      'current_user[[:space:]]*<>[[:space:]]*''service_role''',
      'coalesce(auth.jwt()->>''role'','''') <> ''service_role''',
      'g'
    );
    execute v_sql;
  end loop;
end
$$;
commit;
