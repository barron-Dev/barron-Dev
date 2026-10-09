from cyclothone.dna.extractor import DNAExtractor, TOTAL_DIM, EXTRACTOR_VERSION, SCHEMA_HASH

def test_dimensions_and_versioned_schema():
    fp = DNAExtractor().extract({"tools":["x"],"mitre_techniques":["T1059"]})
    assert len(fp.vector) == TOTAL_DIM == 984
    assert fp.extractor_version == EXTRACTOR_VERSION
    assert fp.schema_hash == SCHEMA_HASH
    assert 0 < fp.coverage <= 1

def test_deterministic():
    payload={"domains":["abc-example.com"],"activity_hours":[1,1,2],"text_sample":"urgent action kindly"}
    a=DNAExtractor().extract(payload)
    b=DNAExtractor().extract(payload)
    assert a.vector == b.vector
    assert a.traits == b.traits
    assert a.trait_ids == b.trait_ids

def test_language_markers_are_non_geographic():
    fp=DNAExtractor().extract({"text_sample":"do the needful, revert back"})
    assert "needful_phrase" in fp.traits["language_markers"]
    assert "indian_english" not in fp.traits.get("language_markers",[])
    assert "west_african_english" not in fp.traits.get("language_markers",[])

def test_invalid_numeric_input_does_not_poison_vector():
    fp=DNAExtractor().extract({"beacon_interval_seconds":float("nan"),"stage_delays_seconds":[float("inf"),-1]})
    assert all(__import__("math").isfinite(x) for x in fp.vector)
