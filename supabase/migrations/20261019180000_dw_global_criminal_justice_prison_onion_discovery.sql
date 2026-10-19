-- Cyclothone DW public criminal-justice / corrections / cybercrime source expansion.
-- Catalog and queue only: no onion addresses are asserted, fetched, or trusted by this migration.
-- Do not apply to production until reviewed and release-approved.

INSERT INTO public.dw_source_categories (slug, display_name, description)
VALUES
  ('corrections_prisons', 'Corrections and Prisons', 'Public, lawful corrections agency notices, prison oversight reports, policy disclosures, and official incident statements. Not individual prisoner tracking.'),
  ('criminal_justice_public_records', 'Criminal Justice Public Records', 'Official court, prosecutor, police, and justice agency releases and public records.'),
  ('cybercrime_public_advisories', 'Cybercrime Public Advisories', 'Public law-enforcement and national cyber-response advisories about cybercrime, extortion claims, and threat actor activity.'),
  ('onion_threat_intel_discovery', 'Onion Threat Intelligence Discovery', 'Discovery of publicly reachable onion threat-intelligence reporting and public-interest leak claims; candidate-only until Tor reachability and content are validated.')
ON CONFLICT (slug) DO UPDATE
SET display_name = EXCLUDED.display_name,
    description = EXCLUDED.description;

INSERT INTO public.dw_sector_source_catalog
  (id, display_name, category_slug, source_url, source_role, access_method, provenance, integration_status, last_check_result, metadata)
VALUES
  ('interpol_public_notices', 'INTERPOL Public Notices', 'criminal_justice_public_records', 'https://www.interpol.int/How-we-work/Notices', 'official_public_notices', 'public_web', 'official_interpol', 'catalogued_not_integrated', 'not_checked', '{"scope":"global","content_policy":"public notices only"}'::jsonb),
  ('europol_press_releases', 'Europol News and Press Releases', 'criminal_justice_public_records', 'https://www.europol.europa.eu/media-press/newsroom', 'official_public_advisory', 'public_web', 'official_europol', 'catalogued_not_integrated', 'not_checked', '{"scope":"europe","content_policy":"public releases only"}'::jsonb),
  ('fbi_press_releases', 'FBI Press Releases', 'criminal_justice_public_records', 'https://www.fbi.gov/news/press-releases', 'official_public_advisory', 'public_web', 'official_fbi', 'catalogued_not_integrated', 'not_checked', '{"scope":"united_states","content_policy":"public releases only"}'::jsonb),
  ('fbi_ic3_publications', 'FBI Internet Crime Complaint Center Publications', 'cybercrime_public_advisories', 'https://www.ic3.gov/PSA', 'official_cybercrime_advisory', 'public_web', 'official_fbi_ic3', 'catalogued_not_integrated', 'not_checked', '{"scope":"united_states_global_relevance","content_policy":"public advisories"}'::jsonb),
  ('us_cisa_alerts', 'CISA Cybersecurity Advisories', 'cybercrime_public_advisories', 'https://www.cisa.gov/news-events/cybersecurity-advisories', 'official_cyber_advisory', 'public_web', 'official_cisa', 'catalogued_not_integrated', 'not_checked', '{"scope":"united_states_global_relevance"}'::jsonb),
  ('us_doj_press_releases', 'US Department of Justice Press Releases', 'criminal_justice_public_records', 'https://www.justice.gov/news', 'official_public_advisory', 'public_web', 'official_us_doj', 'catalogued_not_integrated', 'not_checked', '{"scope":"united_states","content_policy":"public releases"}'::jsonb),
  ('uk_national_crime_agency_news', 'UK National Crime Agency News', 'criminal_justice_public_records', 'https://www.nationalcrimeagency.gov.uk/news', 'official_public_advisory', 'public_web', 'official_uk_nca', 'catalogued_not_integrated', 'not_checked', '{"scope":"united_kingdom","content_policy":"public releases"}'::jsonb),
  ('uk_ncsc_guidance', 'UK National Cyber Security Centre Guidance', 'cybercrime_public_advisories', 'https://www.ncsc.gov.uk/section/keep-up-to-date/all-technical-guidance', 'official_cyber_advisory', 'public_web', 'official_uk_ncsc', 'catalogued_not_integrated', 'not_checked', '{"scope":"united_kingdom_global_relevance"}'::jsonb),
  ('canada_rcmp_news', 'Royal Canadian Mounted Police News', 'criminal_justice_public_records', 'https://www.rcmp-grc.gc.ca/en/news', 'official_public_advisory', 'public_web', 'official_rcmp', 'catalogued_not_integrated', 'not_checked', '{"scope":"canada"}'::jsonb),
  ('australia_afp_news', 'Australian Federal Police News', 'criminal_justice_public_records', 'https://www.afp.gov.au/news-centre', 'official_public_advisory', 'public_web', 'official_afp', 'catalogued_not_integrated', 'not_checked', '{"scope":"australia"}'::jsonb),
  ('new_zealand_police_news', 'New Zealand Police News', 'criminal_justice_public_records', 'https://www.police.govt.nz/news', 'official_public_advisory', 'public_web', 'official_nz_police', 'catalogued_not_integrated', 'not_checked', '{"scope":"new_zealand"}'::jsonb),
  ('unodc_publications', 'UN Office on Drugs and Crime Publications', 'criminal_justice_public_records', 'https://www.unodc.org/unodc/en/publications.html', 'international_publication', 'public_web', 'official_unodc', 'catalogued_not_integrated', 'not_checked', '{"scope":"global","content_policy":"public reports"}'::jsonb),
  ('coe_cpt_publications', 'Council of Europe Committee for the Prevention of Torture', 'corrections_prisons', 'https://www.coe.int/en/web/cpt', 'prison_oversight_publication', 'public_web', 'official_council_of_europe', 'catalogued_not_integrated', 'not_checked', '{"scope":"europe","content_policy":"public oversight reports"}'::jsonb),
  ('world_prison_brief', 'World Prison Brief', 'corrections_prisons', 'https://www.prisonstudies.org/world-prison-brief-data', 'prison_system_research', 'public_web', 'institute_for_crime_and_justice_policy_research', 'catalogued_not_integrated', 'not_checked', '{"scope":"global","content_policy":"aggregated system-level research; no individual tracking"}'::jsonb),
  ('prison_insider', 'Prison Insider', 'corrections_prisons', 'https://www.prison-insider.com/en', 'prison_conditions_reporting', 'public_web', 'public_interest_organization', 'catalogued_not_integrated', 'not_checked', '{"scope":"multi_country","content_policy":"public reporting"}'::jsonb),
  ('africapol_public_news', 'AFRIPOL Public Information', 'criminal_justice_public_records', 'https://afripol.africa-union.org/', 'regional_law_enforcement_public_info', 'public_web', 'official_afripol_candidate', 'catalogued_not_integrated', 'not_checked', '{"scope":"africa","note":"official endpoint and content availability require validation"}'::jsonb),
  ('aseanapol_public_news', 'ASEANAPOL Public Information', 'criminal_justice_public_records', 'https://www.aseanapol.org/', 'regional_law_enforcement_public_info', 'public_web', 'official_aseanapol_candidate', 'catalogued_not_integrated', 'not_checked', '{"scope":"southeast_asia","note":"official endpoint and content availability require validation"}'::jsonb),
  ('ahmia_onion_discovery_index', 'Ahmia Public Onion Discovery Index', 'onion_threat_intel_discovery', 'https://ahmia.fi/', 'candidate_discovery_index', 'public_web', 'public_search_index', 'catalogued_not_integrated', 'not_checked', '{"scope":"global","is_threat_feed":false,"candidate_only":true,"must_validate_onion_over_tor":true}'::jsonb),
  ('tor_project_onion_services', 'Tor Project Onion Services Directory and Documentation', 'onion_threat_intel_discovery', 'https://community.torproject.org/onion-services/', 'onion_service_documentation', 'public_web', 'official_tor_project', 'catalogued_not_integrated', 'not_checked', '{"scope":"global","is_threat_feed":false,"candidate_only":true}'::jsonb)
ON CONFLICT (id) DO UPDATE
SET display_name = EXCLUDED.display_name,
    category_slug = EXCLUDED.category_slug,
    source_url = EXCLUDED.source_url,
    source_role = EXCLUDED.source_role,
    access_method = EXCLUDED.access_method,
    provenance = EXCLUDED.provenance,
    integration_status = EXCLUDED.integration_status,
    last_check_result = EXCLUDED.last_check_result,
    metadata = EXCLUDED.metadata,
    updated_at = now();

-- Queue one bounded discovery task per country/region and each relevant public-source class.
-- No candidate URL is fabricated. These tasks are discovery requests, not known onion hosts.
WITH target_scopes AS (
  SELECT scope_key
  FROM public.dw_geographic_scopes
  WHERE iso_alpha2 IS NOT NULL
     OR lower(scope_type) IN ('country', 'region', 'subregion', 'territory')
),
work AS (
  SELECT scope_key, 'criminal_justice_public_records'::text AS category_slug,
         'official_criminal_justice_source_discovery'::text AS discovery_kind
  FROM target_scopes
  UNION ALL
  SELECT scope_key, 'corrections_prisons',
         'official_corrections_prison_source_discovery'
  FROM target_scopes
  UNION ALL
  SELECT scope_key, 'cybercrime_public_advisories',
         'public_cybercrime_advisory_source_discovery'
  FROM target_scopes
  UNION ALL
  SELECT scope_key, 'onion_threat_intel_discovery',
         'public_onion_threat_intel_candidate_discovery'
  FROM target_scopes
)
INSERT INTO public.dw_source_discovery_queue
  (scope_key, category_slug, discovery_kind, candidate_url, candidate_host,
   discovery_provenance, queue_status, attempt_count, next_attempt_at,
   result_metadata, language_code, religion_slug)
SELECT w.scope_key, w.category_slug, w.discovery_kind, NULL, NULL,
       'migration:global_public_criminal_justice_and_onion_discovery_catalog_20261019',
       'queued', 0, now(),
       jsonb_build_object(
         'candidate_only', true,
         'source_class', w.discovery_kind,
         'safety_policy', 'public_sources_only_no_illicit_marketplace_access_no_stolen_dataset_ingestion',
         'onion_policy', 'discover_candidates_from_public_indexes_then_validate_v3_host_and_tor_route_before_fetch',
         'country_attribution', 'must_be_supported_by_source_provenance_not_inferred_from_language_or_topic'
       ),
       NULL, NULL
FROM work w
WHERE NOT EXISTS (
  SELECT 1 FROM public.dw_source_discovery_queue q
  WHERE q.scope_key = w.scope_key
    AND q.category_slug = w.category_slug
    AND q.discovery_kind = w.discovery_kind
    AND q.candidate_url IS NULL
    AND q.discovery_provenance = 'migration:global_public_criminal_justice_and_onion_discovery_catalog_20261019'
);
