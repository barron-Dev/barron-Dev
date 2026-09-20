-- Reconcile existing Trust signing-domain implementations without duplicating them.
-- The existing function bodies are preserved; only the known incorrect domain literals are replaced.
do $$
declare src text;
begin
 select pg_get_functiondef(p.oid) into src from pg_proc p join pg_namespace n on n.oid=p.pronamespace
 where n.nspname='public' and p.proname='trust_register_signing_key'
 and pg_get_function_identity_arguments(p.oid)='uuid, text, text, text, text, timestamp with time zone, timestamp with time zone';
 if src is null then raise exception 'trust_register_signing_key_missing'; end if;
 src:=replace(src, 'p_purpose not in (''TRUST_PROOF'',''TRUST_CERTIFICATE'')', 'p_purpose not in (''TRUST_ATTESTATION'',''TRUST_PROOF'',''TRUST_CERTIFICATE'')');
 execute src;
end $$;

do $$
declare src text;
begin
 select pg_get_functiondef(p.oid) into src from pg_proc p join pg_namespace n on n.oid=p.pronamespace
 where n.nspname='public' and p.proname='trust_verify_certificate_chain'
 and pg_get_function_identity_arguments(p.oid)='uuid';
 if src is null then raise exception 'trust_verify_certificate_chain_missing'; end if;
 src:=replace(src, 'purpose=''TRUST_CERTIFICATE'' and algorithm=''ED25519'';', 'purpose=''TRUST_AUTHORITY'' and algorithm=''ED25519'';');
 execute src;
end $$;