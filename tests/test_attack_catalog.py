from cyclothone.attribution.attack_catalog import _extract_actor_profiles, _extract_techniques


def test_official_stix_catalogue_extracts_techniques_and_actor_aliases():
    bundle = {"objects": [
        {"type": "attack-pattern", "id": "attack-pattern--1", "name": "PowerShell", "external_references": [{"source_name": "mitre-attack", "external_id": "T1059.001", "url": "https://attack.mitre.org/techniques/T1059/001/"}], "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}]},
        {"type": "intrusion-set", "id": "intrusion-set--1", "name": "Example Group", "x_mitre_aliases": ["Alias A"], "external_references": [{"source_name": "mitre-attack", "external_id": "G0007", "url": "https://attack.mitre.org/groups/G0007/"}], "created": "2020-01-01T00:00:00Z", "modified": "2024-01-01T00:00:00Z"},
        {"type": "relationship", "id": "relationship--1", "relationship_type": "uses", "source_ref": "intrusion-set--1", "target_ref": "attack-pattern--1"},
    ]}
    techniques = _extract_techniques(bundle)
    actors = _extract_actor_profiles(bundle)
    assert techniques[0]["technique_id"] == "T1059.001"
    assert actors[0]["actor_id"] == "mitre-attack-G0007"
    assert actors[0]["aliases"] == ["Alias A"]
    assert actors[0]["profile"]["attack_techniques"] == ["T1059.001"]
