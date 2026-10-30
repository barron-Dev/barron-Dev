from cyclothone.compliance.catalog import CONTROLS, FRAMEWORKS, controls_for


def test_reference_catalogue_matches_reconciled_live_control_count():
    assert len(CONTROLS) == 30
    assert len({control["id"] for control in CONTROLS}) == 30


def test_hipaa_live_seed_controls_have_stable_ids():
    controls = {control["code"]: control for control in controls_for("hipaa")}
    assert controls["164.308(a)(1)"]["id"] == "hipaa.164.308.a.1"
    assert controls["164.312(b)"]["id"] == "hipaa.164.312.b"
    assert controls["164.308(a)(7)"]["id"] == "hipaa.164.308.a.7"


def test_all_framework_controls_have_unique_ids_and_valid_framework_membership():
    assert {str(control["framework"]) for control in CONTROLS} == set(FRAMEWORKS)
    ids = [str(control["id"]) for control in CONTROLS]
    assert len(ids) == len(set(ids))
    for framework in FRAMEWORKS:
        framework_controls = controls_for(framework)
        assert framework_controls
        assert all(control["framework"] == framework for control in framework_controls)
        assert all(isinstance(control["id"], str) and control["id"].strip() for control in framework_controls)
