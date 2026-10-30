from cyclothone.compliance.catalog import CONTROLS, controls_for


def test_reference_catalogue_matches_reconciled_live_control_count():
    assert len(CONTROLS) == 30
    assert len({control["id"] for control in CONTROLS}) == 30


def test_hipaa_live_seed_controls_have_stable_ids():
    controls = {control["code"]: control for control in controls_for("hipaa")}
    assert controls["164.308(a)(1)"]["id"] == "hipaa.164.308.a.1"
    assert controls["164.312(b)"]["id"] == "hipaa.164.312.b"
    assert controls["164.308(a)(7)"]["id"] == "hipaa.164.308.a.7"


def test_all_framework_controls_use_unique_stable_ids():
    for framework in {str(control["framework"]) for control in CONTROLS}:
        framework_controls = controls_for(framework)
        ids = [str(control["id"]) for control in framework_controls]
        assert len(ids) == len(set(ids))
        assert all(value.startswith(f"{framework}.") for value in ids)
