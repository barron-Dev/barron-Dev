-- Close cryptographic signing-domain boundaries on existing key registries.
do $$ begin
  if not exists (select 1 from pg_constraint where conrelid='public.trust_signing_keys'::regclass and conname='trust_signing_keys_domain_check') then
    alter table public.trust_signing_keys add constraint trust_signing_keys_domain_check
      check (algorithm='ED25519' and purpose in ('TRUST_ATTESTATION','TRUST_PROOF','TRUST_CERTIFICATE'));
  end if;
  if not exists (select 1 from pg_constraint where conrelid='public.signing_keys'::regclass and conname='signing_keys_domain_check') then
    alter table public.signing_keys add constraint signing_keys_domain_check
      check (algorithm='Ed25519' and purpose in ('COMMAND','AI_ENVELOPE','FEDERATION','COMPLIANCE'));
  end if;
end $$;
create unique index if not exists trust_signing_keys_one_active_domain
  on public.trust_signing_keys(tenant_id,purpose) where status='ACTIVE';
create unique index if not exists signing_keys_one_active_domain
  on public.signing_keys(purpose) where active=true;
