begin;

insert into public.giril_ref_sources
(source_key,name,authority_level,source_kind,jurisdiction_code,source_url,api_base_url,licensing_notes,update_policy,status)
values
('ISO_3166_MA','ISO 3166 Maintenance Agency','PRIMARY','STANDARDS',null,'https://www.iso.org/iso-3166-country-codes.html',null,'ISO states that country codes are free to use; bulk Country Codes Collection is a paid update service. Do not scrape or redistribute paid collection data without the applicable rights.','Use current ISO 3166 country/subdivision data with source version and effective dates.','UNINITIALIZED'),
('IANA_ROOT_ZONE','IANA Root Zone Database','PRIMARY','DNS',null,'https://www.iana.org/domains/root/db','https://data.iana.org/TLD/tlds-alpha-by-domain.txt',null,'Refresh delegated TLD data from the current IANA publication; retain source/version metadata.','UNINITIALIZED'),
('GLEIF_GLOBAL_LEI','Global Legal Entity Identifier Foundation','PRIMARY','IDENTITY',null,'https://www.gleif.org/en/lei-data/gleif-api/','https://api.gleif.org/api/v1',null,'Use current GLEIF API/data and record source version/freshness; do not copy third-party company mirrors as authoritative.','UNINITIALIZED')
on conflict (source_key) do update set
 name=excluded.name,
 authority_level=excluded.authority_level,
 source_kind=excluded.source_kind,
 source_url=excluded.source_url,
 api_base_url=excluded.api_base_url,
 licensing_notes=excluded.licensing_notes,
 update_policy=excluded.update_policy,
 status=excluded.status,
 updated_at=now();

commit;