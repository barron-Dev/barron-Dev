import numpy as np
import pytest

from sentinel.ml.runtime import OnnxModel
from sentinel.ml.train import MIN_SAMPLES, export_onnx, train_model


def _payload(i: int) -> dict:
    return {
        "entropy": 3.0 + (i % 7) * 0.2,
        "signed": i % 5 == 0,
        "is_packed": i % 11 == 0,
        "size": float(1000 + i * 17),
        "suspicious_imports": ["x"] * (i % 4),
        "network_connections": float(i % 9),
        "child_processes": float(i % 6),
        "file_writes": float(i % 8),
        "registry_writes": float(i % 3),
        "encrypts_files": i % 13 == 0,
        "network_beacon": i % 17 == 0,
    }


@pytest.mark.asyncio
async def test_onnx_inference_roundtrip():
    payloads = [_payload(i) for i in range(MIN_SAMPLES * 2)]
    from sentinel.ml.features import extract

    X = np.vstack([extract("file", p) for p in payloads])
    y = (X[:, 0] + X[:, 10] + X[:, 17] > 3.0).astype(np.int32)
    weights = np.ones(len(y), dtype=np.float32)
    pipeline, _ = train_model(X, y, weights)

    expected = pipeline.predict_proba(X[:8])[:, 1]
    model = OnnxModel.from_bytes(export_onnx(pipeline), version=1)
    actual = np.asarray([
        await model.predict_proba("file", payloads[i]) for i in range(8)
    ])
    np.testing.assert_allclose(actual, expected, atol=1e-4)
