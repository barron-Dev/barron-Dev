# Production migration source reconciliation inventory — 2026-10-29

## Status

**BLOCKED — inventory captured; migration history is not reconciled.** This document does not authorize or perform a production migration, schema repair, merge, or deployment.

## Read-only observations

- Supabase project: `whcomikcftbousoqzeal`
- Live migration ledger entries returned: **221**
- Latest live migration version: **20261025065948** (`controlled_owner_bootstrap_characeopriv_20261025`)
- SQL files visible in `main:supabase/migrations`: **24**
- Live ledger versions that do not exactly match a checked-in migration filename prefix: **219**
- Live public tables whose names include `watchtower`: **0**

This is a filename/version inventory, not proof that every unmatched ledger row is missing its original source: historical migrations may have been renamed, superseded, squashed, or recorded under a different version. The checked-in directory is not sufficient to reconstruct the production history by replaying SQL.

## Required reconciliation procedure

1. Freeze new production DDL until the source ledger is reconciled.
2. Recover original migration files from Git history, pull requests, release artifacts, and deployment records; retain their original content and checksums.
3. Build a ledger-to-source mapping for every live migration version, including explicit evidence for renamed/replaced migrations. Do not fabricate source for unrecoverable records.
4. Compare the current production schema (tables, columns, constraints, indexes, triggers, policies, routines, grants, extensions) with the recovered migration intent and current repository state.
5. Classify every difference as source-history gap, schema drift, intentional live-only change, or repository-only change; assign an owner and evidence reference.
6. Validate the mapping and any forward-only repair migration against a production-like clone/branch. A repair migration must be idempotent where appropriate, tenant-safe, and non-destructive.
7. Apply only reviewed forward-only repair migrations, then re-read the migration ledger and schema and run security advisors plus authenticated end-to-end tests.
8. Record the exact commit, migration version, resulting schema evidence, test runs, and rollback/forward-fix plan.

## Live ledger rows without an exact checked-in filename prefix

- `20260915210754` — `add_device_enrollment_security`
- `20260915211227` — `add_provisioning_enrollment_rpc`
- `20260915220047` — `response_and_intel`
- `20260915220316` — `vault_and_intel`
- `20260915220320` — `vault_secret_lookup`
- `20260915220931` — `realtime_and_autocase`
- `20260915235506` — `deception_layer`
- `20260916000304` — `deception_autocase_bridge`
- `20260916001626` — `deception_security_hardening`
- `20260916004648` — `investigation_control_plane`
- `20260916004748` — `investigation_session_compatibility`
- `20260916005400` — `investigation_start_claim`
- `20260916011254` — `data_trust_exfiltration_control`
- `20260916013002` — `data_trust_channel_expansion`
- `20260916014358` — `data_trust_enforcement`
- `20260916014447` — `data_trust_enforcement_report`
- `20260916015754` — `ai_agent_security`
- `20260916020842` — `026_hunting`
- `20260916021844` — `027_compliance`
- `20260916022425` — `compliance_control_library`
- `20260916022759` — `compliance_catalog_seed`
- `20260916022851` — `compliance_hardening`
- `20260916022915` — `compliance_security_hardening`
- `20260916023433` — `compliance_snapshot_verification`
- `20260916023455` — `compliance_signing_rpc_hardening`
- `20260916052557` — `029_federation`
- `20260916053900` — `030_federation_reputation_repair`
- `20260916054931` — `federation_operational_hardening`
- `20260916055222` — `031_federation_detection_promotion`
- `20260916055936` — `physical_digital_convergence`
- `20260916062014` — `physical_operational_hardening`
- `20260916072343` — `security_function_hardening`
- `20260916072450` — `security_function_search_paths`
- `20260916072732` — `038_security_function_hardening`
- `20260917212136` — `security_surface_hardening`
- `20260918005253` — `rename_signing_key_secret_prefix_to_cyclothone`
- `20260918110744` — `add_cyclothone_regions`
- `20260918112116` — `align_regions_residency_schema`
- `20260918112447` — `040_darkweb_runtime_alignment`
- `20260918112744` — `041_darkweb_alias_runtime_fix`
- `20260918120824` — `007_unified_response_runtime_alignment`
- `20260918123254` — `darkweb_source_enablement`
- `20260918180732` — `047_device_enrollment_token_issuance`
- `20260919054437` — `harden_blast_radius_rpc_execute_privileges`
- `20260919144621` — `067_ai_execution_binding`
- `20260919144626` — `068_ai_provider_binding_authority`
- `20260919144631` — `069_ai_mission_dag`
- `20260919144636` — `070_ai_mission_authority`
- `20260919144641` — `071_ai_foundation_kernel`
- `20260919144647` — `072_ai_execution_admission_kernel`
- `20260919144652` — `073_ai_security_decision_boundary`
- `20260919144909` — `074_ai_execution_provenance_and_replay_kernel_core`
- `20260919144918` — `075_ai_execution_authority_integration`
- `20260919144923` — `076_ai_mission_execution_authority`
- `20260919144928` — `077_ai_execution_commit_guard`
- `20260919144933` — `078_ai_destructive_approval_kernel`
- `20260919144938` — `079_ai_worker_lease_recovery`
- `20260919144943` — `080_ai_worker_lease_transition_hardening`
- `20260919144953` — `081_workforce_identity_authority`
- `20260919144958` — `082_workforce_ai_mission_boundary`
- `20260919145003` — `083_workforce_ai_turn_admission`
- `20260919145007` — `084_workforce_ai_run_binding`
- `20260919145012` — `085_workforce_ai_execution_authority`
- `20260919145050` — `086_canonical_execution_commit_atomicity_fixed`
- `20260919145058` — `087_workforce_atomic_execution_bridge`
- `20260919145103` — `088_run_bound_execution_authority`
- `20260919145107` — `089_execution_outcome_settlement`
- `20260919145112` — `090_device_result_execution_bridge`
- `20260919145116` — `091_workforce_execution_outcome_unification`
- `20260919145121` — `092_execution_liveness_watchdog`
- `20260919145216` — `093_execution_outcome_audit_fixed`
- `20260919145223` — `094_execution_outcome_boundary_hardening`
- `20260919145228` — `095_ai_execution_binding_registry`
- `20260919145247` — `096_workforce_run_start_hardening_fixed`
- `20260919145255` — `097_atomic_device_command_execution`
- `20260919145351` — `098_ai_security_runtime_hardening`
- `20260919161932` — `ai_provider_usage_settlement`
- `20260919182741` — `customer_identity_and_service_requests_v2`
- `20260919182751` — `customer_admission_v2`
- `20260919182802` — `customer_workspace_approval_v2`
- `20260919182809` — `customer_service_admission_gate`
- `20260919184010` — `customer_membership_controls_v1`
- `20260919184120` — `customer_invitation_acceptance_v1`
- `20260919184301` — `customer_case_service_lifecycle_v1`
- `20260919184435` — `customer_case_lifecycle_controls_v1`
- `20260919184459` — `customer_case_assignment_rpc_v1`
- `20260919205218` — `trust_core_registry_v1`
- `20260919205431` — `trust_attestation_evidence_v1`
- `20260919205614` — `trust_state_engine_v1_fix`
- `20260919205757` — `trust_proof_engine_v1`
- `20260919205932` — `trust_signing_authority_v1`
- `20260919210433` — `trust_certificate_authority_v1`
- `20260919210453` — `trust_certificate_authority_tenant_keys_v1`
- `20260919210821` — `trust_authority_hardening_v1`
- `20260919210955` — `trust_policy_assurance_v1`
- `20260919211304` — `ai_trust_execution_boundary_v1`
- `20260919211319` — `trust_policy_binding_hardening_v1`
- `20260919211754` — `ai_trust_registry_sync_v1`
- `20260919211811` — `ai_trust_registry_sync_corrections_v1`
- `20260919212335` — `ai_trust_execution_identity_graph_v1`
- `20260919212350` — `ai_trust_execution_identity_authority_v1`
- `20260919212601` — `trust_execution_component_policy_v1`
- `20260919212622` — `trust_execution_component_policy_correction_v1`
- `20260919212640` — `trust_component_policy_integrity_v1`
- `20260919213259` — `trust_evidence_cryptographic_verification_v1`
- `20260919213846` — `trust_attestation_cryptographic_binding_v1`
- `20260919213914` — `trust_evidence_immutability_v1`
- `20260920031454` — `trust_evidence_content_integrity_v1`
- `20260920031502` — `trust_evidence_immutability_recorder_correction_v1`
- `20260920031635` — `trust_policy_content_integrity_v1`
- `20260920031931` — `trust_attestation_signing_authority_v1`
- `20260920031941` — `trust_attestation_signature_hardening_v1`
- `20260920032355` — `trust_measurement_snapshot_integrity_v1`
- `20260920032526` — `trust_certificate_policy_binding_v1`
- `20260920032715` — `trust_certificate_full_verification_chain_v1`
- `20260920032839` — `trust_end_to_end_signature_verification_v1`
- `20260920033232` — `trust_public_verification_api_v1`
- `20260920033252` — `trust_public_verification_material_correction_v1`
- `20260920034107` — `trust_public_key_directory_v1`
- `20260920034434` — `trust_public_key_lifecycle_hardening_v1`
- `20260920034802` — `trust_public_key_ceremony_v1`
- `20260920043126` — `trust_certificate_authority_endorsement_rotation_v2`
- `20260920043150` — `trust_certificate_authority_public_material_v1`
- `20260920043209` — `trust_certificate_authority_binding_v1`
- `20260920043356` — `trust_certificate_authority_chain_hardening_v1`
- `20260920043507` — `trust_certificate_authority_remove_legacy_issue_overload_v1`
- `20260920045025` — `trust_authority_key_rotation_ceremony_v1`
- `20260920045421` — `trust_continuous_verification_v1`
- `20260920050253` — `trust_event_ingestion_and_reevaluation`
- `20260920050309` — `trust_automatic_event_wiring_and_queue_worker_v1`
- `20260920050500` — `trust_reevaluation_worker_hardening`
- `20260920051121` — `trust_certificate_reactivation_hardening_v1`
- `20260920051302` — `trust_event_visibility_and_worker_observability_v1`
- `20260920051924` — `trust_worker_heartbeat_observability_v1`
- `20260920110238` — `trust_certificate_capability_gate_v1`
- `20260920111628` — `trust_certificate_subject_issuance_preflight_v1`
- `20260920112422` — `trust_authority_ceremony_crypto_search_path`
- `20260920112509` — `trust_authority_ceremony_and_authority_domain_hardening`
- `20260920144315` — `trust_certificate_issuance_reconciliation_v1`
- `20260920155607` — `trust_security_boundary_closure_v1`
- `20260920155751` — `security_definer_rpc_boundary_v2`
- `20260920202710` — `20260921003000_trust_internal_event_visibility_boundary_v1`
- `20260920214346` — `deprecate_auth_role_service_boundaries_v1`
- `20260920214534` — `ai_execution_duplicate_overload_cleanup_v1`
- `20260920232708` — `canonical_identity_boundary_v1`
- `20260926125426` — `099_recovery_vault_runtime`
- `20260926145211` — `add_customer_verification_review_control`
- `20260926145324` — `align_customer_workspace_approval_verification`
- `20260926145516` — `harden_recovery_policy_grants`
- `20260926145619` — `add_controlled_recovery_policy_provisioning`
- `20260926145753` — `lock_recovery_policy_provisioning_to_control_plane`
- `20260926171307` — `harden_customer_control_rpc_grants`
- `20260927173903` — `mobile_digital_intelligence`
- `20260927175138` — `mdi_function_hardening`
- `20260927195300` — `mdi_parts_1_8_production`
- `20260927195309` — `mdi_rf_consent`
- `20260927195617` — `mdi_runtime_hardening`
- `20260927200007` — `mdi_service_role_policies`
- `20260927213010` — `mdi_attribution_case_ttp_runtime`
- `20260928000720` — `fix_security_definer_service_role_checks`
- `20260928000744` — `normalize_security_definer_service_role_checks`
- `20260928124654` — `mdi_advanced_tenant_lineage`
- `20260928124756` — `mdi_advanced_tenant_lineage_uuid_fix`
- `20260928124839` — `mdi_advanced_alert_tenant_required`
- `20260929000715` — `mdi_evidence_pack_tenant_boundary`
- `20260929044946` — `mdi_canonical_subject_tenant_binding`
- `20261001152054` — `giril_onboarding_rpc_security_hardening`
- `20261001152238` — `giril_verify_rpc_reaffirmation`
- `20261001153705` — `giril_control_admission_gate_v1`
- `20261001153723` — `giril_control_admission_gate_v2`
- `20261001153847` — `giril_control_admission_gate_v3`
- `20261006005600` — `giril_closed_loop_admission`
- `20261006005611` — `giril_admission_case_contact_fix`
- `20261006005631` — `giril_service_role_admission_bridge`
- `20261009062953` — `security_lockdown_admission_membership_rpc_grants`
- `20261009063125` — `fix_org_rls_recursion_and_domain_write_scope`
- `20261009063148` — `harden_default_privileges_public_schema`
- `20261009064112` — `service_request_execution_contract_and_dw_sweep`
- `20261010022457` — `darkweb_release_contract_20261010010000`
- `20261010022501` — `darkweb_paste_feed_replacement_20261010004200`
- `20261011061706` — `fix_dw_finding_upsert_and_disable_hibp`
- `20261011062041` — `keep_darkweb_alerts_out_of_device_detections`
- `20261011062509` — `add_public_social_search_sources`
- `20261012060949` — `tiktok_commercial_content_source`
- `20261012083522` — `darkweb_source_registry_base`
- `20261012083534` — `darkweb_source_registry_supporting_tables`
- `20261017025823` — `047_security_claims`
- `20261017030254` — `048_security_member_helper_hardening`
- `20261017135021` — `20261017120000_native_onion_source`
- `20261017135024` — `20261017150000_native_dw_honeytokens`
- `20261017135027` — `20261017180000_exclude_reddit_source`
- `20261018132005` — `create_venom_onion_seeds_stage`
- `20261019072813` — `dw_global_source_taxonomy_20261019`
- `20261019073136` — `dw_global_taxonomy_expansion_20261019`
- `20261019073250` — `dw_health_taxonomy_expansion_20261019`
- `20261019073406` — `dw_official_health_source_catalog_20261019`
- `20261019073531` — `dw_global_sector_source_catalog_bulk_20261019`
- `20261019073558` — `dw_remaining_sector_catalog_coverage_20261019`
- `20261019075433` — `dw_global_geographic_coverage_foundation_20261019`
- `20261019080344` — `dw_country_category_coverage_and_discovery_queue_20261019`
- `20261019083728` — `dw_global_languages_religions_schema_20261019`
- `20261019083736` — `dw_global_languages_religions_security_20261019`
- `20261019083743` — `dw_onion_probe_provenance_fields_20261019`
- `20261019084125` — `dw_global_language_religion_coverage_matrices_20261019`
- `20261020142712` — `venom_onion_seed_activation_and_provenance`
- `20261020142737` — `allow_active_venom_onion_seed_status`
- `20261021064246` — `dw_seed_taxonomy_honey_canary_source_health`
- `20261021064301` — `dw_securedrop_discovery_registry`
- `20261021064347` — `dw_enforce_seed_domain_isolation_and_append_only_events`
- `20261021064440` — `dw_onion_probe_evidence_and_gated_activation`
- `20261021064504` — `dw_isolated_honeypot_and_canary_event_rpcs`
- `20261021064731` — `dw_discovery_queue_lease_columns`
- `20261021064748` — `dw_discovery_queue_claim_complete_rpc`
- `20261021070050` — `dw_lockdown_new_operational_tables_20261021`
- `20261021070151` — `dw_country_candidate_matrix_and_absence_coverage_20261021`
- `20261021070218` — `dw_country_matrix_existing_seed_reconciliation_20261021`
- `20261021081258` — `dw_discovery_queue_legacy_backlog_quarantine_forward`
- `20261025065850` — `workforce_build_stage_catalog_20261025`
- `20261025065948` — `controlled_owner_bootstrap_characeopriv_20261025`

## Current checked-in migration filenames on main

- `20260921030000_canonical_identity_boundary_v1.sql`
- `20260927173500_mobile_digital_intelligence.sql`
- `20260927175041_mdi_core_algorithms.sql`
- `20260927175200_mdi_function_hardening.sql`
- `20260927220000_mdi_provider_seed.sql`
- `20260927230000_mdi_advanced_gap_layer.sql`
- `20260927233000_mdi_rf_catalog_attribution.sql`
- `20260927235900_mdi_copilot_compliance.sql`
- `20260927235959_mdi_parts_1_8_production.sql`
- `20260928000000_mdi_rf_consent.sql`
- `20260928001000_mdi_runtime_hardening.sql`
- `20260928002000_mdi_service_role_policies.sql`
- `20260928003000_mdi_attribution_case_ttp_runtime.sql`
- `20260928010000_fix_security_definer_service_role_checks.sql`
- `20260928010000_mdi_advanced_gap_layer_runtime_reconciliation.sql`
- `20260928010100_normalize_security_definer_service_role_checks.sql`
- `20261001151838_giril_production_source_catalog_and_onboarding.sql`
- `20261001152000_giril_onboarding_rpc_security_hardening.sql`
- `20261001180000_giril_global_reference_foundation_v1.sql`
- `20261001183000_giril_authoritative_source_catalog_v1.sql`
- `20261001190000_giril_gleif_reference_v1.sql`
- `20261017120000_native_onion_source.sql`
- `20261017150000_native_dw_honeytokens.sql`
- `20261017180000_exclude_reddit_source.sql`

## Watchtower gate

The Watchtower camera registry/probe migration remains source-only on PR #96. Do not apply it until the history/source mapping and target schema constraints have been reviewed. The absence of a table in a table listing is not sufficient proof that a migration is safe to apply.

## Release decision

**Do not declare phase exit yet.** CI passing on Watchtower PR #96 proves the tested commit builds; it does not establish production schema parity, a successful authorized camera connection, detector/model operation, durable signed evidence, or tenant-authenticated end-to-end behavior.
