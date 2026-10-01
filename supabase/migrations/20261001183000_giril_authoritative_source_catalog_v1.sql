begin;

insert into public.giril_ref_sources
(source_key,name,authority_level,source_kind,jurisdiction_code,source_url,update_policy,status)
values
('ISO_3166_MA','ISO 3166 Maintenance Agency','PRIMARY','STANDARDS',null,'https://www.iso.org/iso-3166-country-codes.html','Use current ISO 3166 country/subdivision data; retain source version and effective dates.','ACTIVE'),
('IANA_ROOT_ZONE','IANA Root Zone Database','PRIMARY','DNS',null,'https://www.iana.org/domains/root/db','Refresh delegated TLD data from the current IANA root-zone publication.','ACTIVE'),
('GLEIF_GLOBAL_LEI','Global Legal Entity Identifier Foundation','PRIMARY','IDENTITY',null,'https://www.gleif.org/en/lei-data/gleif-api/','Use current GLEIF API / Golden Copy data and record source version/freshness.','ACTIVE')
on conflict (source_key) do update set
 name=excluded.name,
 authority_level=excluded.authority_level,
 source_kind=excluded.source_kind,
 source_url=excluded.source_url,
 update_policy=excluded.update_policy,
 status=excluded.status,
 updated_at=now();

commit;