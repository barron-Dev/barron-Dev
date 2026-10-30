from pathlib import Path


def test_vip_assignment_schema_is_purpose_bound_and_short_lived():
    root = Path(__file__).resolve().parents[1]
    sql = (root / "supabase/migrations/20261030160000_ephemeral_assignment_audit_v1.sql").read_text()
    assert "end_time <= start_time + interval '14 days'" in sql
    assert "status = 'pending_approval'" in sql
    assert "created_by <> trim(p_actor)" in sql
    assert "consent_evidence_sha256" in sql
    assert "authorization_ref_sha256" in sql
    assert "create table if not exists public.vip_assignment_events" in sql
    assert "vip_assignment_event_immutable" in sql
    assert "cron.schedule(" in sql
    assert "0 * * * *" in sql
    assert "purge_expired_vip_data" in sql


def test_location_tracking_is_not_part_of_phase_two_schema_or_api():
    root = Path(__file__).resolve().parents[1]
    sql = (root / "supabase/migrations/20261030160000_ephemeral_assignment_audit_v1.sql").read_text()
    route = (root / "src/cyclothone/api/routes/vip_protection.py").read_text()
    assert "vip_location_pings" not in sql
    assert "latitude" not in sql.lower()
    assert "longitude" not in sql.lower()
    assert "source_metadata" in route
    assert "region_code" in route
    assert "precise_personal_location_used" in route
    assert "haversine" not in route.lower()
    assert "location_collection" in route


def test_sos_requires_active_assignment_and_never_dispatches_automatically():
    root = Path(__file__).resolve().parents[1]
    sql = (root / "supabase/migrations/20261030160000_ephemeral_assignment_audit_v1.sql").read_text()
    route = (root / "src/cyclothone/api/routes/vip_protection.py").read_text()
    assert "status = 'active' and start_time <= now() and end_time > now()" in sql
    assert "'not_dispatched'" in sql
    assert "human_response_required" in route
    assert "physical_controls_changed" in route
    assert "vip:manage" in route
    assert "vip:approve" in route
    assert "vip:correlate" in route
    assert "vip:sos" in route


def test_regional_threat_match_is_source_bound_and_intent_neutral():
    root = Path(__file__).resolve().parents[1]
    sql = (root / "supabase/migrations/20261030160000_ephemeral_assignment_audit_v1.sql").read_text()
    route = (root / "src/cyclothone/api/routes/vip_protection.py").read_text()
    assert "unique (assignment_id, threat_finding_id)" in sql
    assert "threat_evidence_sha256" in sql
    assert "metadata.get(\"region_code\")" in route
    assert "metadata.get(\"observed_at\")" in route
    assert "confidence\": \"not_assigned\"" in route
    assert "intent_inference\": False" in route
