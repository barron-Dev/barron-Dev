import numpy as np
import pytest

from cyclothone.ml.features import FEATURE_NAMES
from sentinel.ml.train import MIN_SAMPLES, NotEnoughData, train_model


def test_rejects_small_dataset():
    X = np.zeros((10, len(FEATURE_NAMES)), dtype=np.float32)
    y = np.zeros(10, dtype=np.int32)
    weights = np.ones(10, dtype=np.float32)
    with pytest.raises(NotEnoughData):
        train_model(X, y, weights)


def test_train_produces_metrics():
    rng = np.random.default_rng(42)
    n = MIN_SAMPLES * 2
    X = rng.normal(size=(n, len(FEATURE_NAMES))).astype(np.float32)
    y = (X[:, 0] + X[:, 1] > 0).astype(np.int32)
    weights = np.ones(n, dtype=np.float32)
    _, metrics = train_model(X, y, weights)
    assert 0.0 <= metrics["auc"] <= 1.0
    assert metrics["auc"] > 0.7
    assert {"precision", "recall", "f1"}.issubset(metrics)
