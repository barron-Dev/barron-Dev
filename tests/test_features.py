import numpy as np

from cyclothone.ml.features import FEATURE_NAMES, extract


def test_extract_shape_dtype_and_finiteness():
    vector = extract("process", {"encrypts_files": True, "entropy": 7.9})
    assert vector.shape == (len(FEATURE_NAMES),)
    assert vector.dtype == np.float32
    assert np.isfinite(vector).all()


def test_missing_fields_are_zero_except_kind_flag():
    vector = extract("file", {})
    assert vector[:-6].sum() == 0.0
    assert vector[-6:].sum() == 1.0


def test_kind_one_hot():
    for kind in ("process", "file", "network", "registry", "sensor", "identity"):
        assert extract(kind, {})[-6:].sum() == 1.0


def test_nonfinite_input_is_sanitized():
    vector = extract("file", {"entropy": float("nan"), "size": float("inf")})
    assert np.isfinite(vector).all()
