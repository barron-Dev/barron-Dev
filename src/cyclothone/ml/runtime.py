from __future__ import annotations

import asyncio
import hashlib
import logging
from typing import Any

import numpy as np
import onnxruntime as ort

from cyclothone.ml.features import FEATURE_NAMES, extract

logger = logging.getLogger(__name__)


class OnnxModel:
    def __init__(self, session: ort.InferenceSession, version: int, sha256: str) -> None:
        self.session = session
        self.version = version
        self.sha256 = sha256
        inputs = session.get_inputs()
        outputs = session.get_outputs()
        if len(inputs) != 1 or len(outputs) < 1:
            raise ValueError("invalid Cyclothone ONNX model interface")
        self._input_name = inputs[0].name
        self._output_names = [output.name for output in outputs]

    @classmethod
    def from_bytes(cls, data: bytes, version: int, expected_sha256: str | None = None) -> "OnnxModel":
        actual = hashlib.sha256(data).hexdigest()
        if expected_sha256 and actual != expected_sha256:
            raise ValueError("model artifact SHA-256 mismatch")
        options = ort.SessionOptions()
        options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        options.intra_op_num_threads = 1
        options.inter_op_num_threads = 1
        session = ort.InferenceSession(
            data, sess_options=options, providers=["CPUExecutionProvider"],
        )
        shape = session.get_inputs()[0].shape
        if len(shape) != 2 or shape[1] not in (len(FEATURE_NAMES), "None"):
            raise ValueError("ONNX input feature dimension does not match Cyclothone schema")
        return cls(session, version, actual)

    async def predict_proba(self, event_type: str, payload: dict[str, Any]) -> float:
        vector = extract(event_type, payload).reshape(1, -1)
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._run_sync, vector)

    def _run_sync(self, vector: np.ndarray) -> float:
        outputs = self.session.run(None, {self._input_name: vector})
        if not outputs:
            raise RuntimeError("ONNX model returned no outputs")
        probability = _probability_from_outputs(outputs)
        if not np.isfinite(probability) or not 0.0 <= probability <= 1.0:
            raise RuntimeError("ONNX model returned invalid probability")
        return probability


def _probability_from_outputs(outputs: list[Any]) -> float:
    # zipmap=false classifiers normally return [N, 2] probabilities.
    for output in outputs:
        array = np.asarray(output)
        if array.ndim == 2 and array.shape[1] == 2:
            return float(array[0, 1])
    for output in outputs:
        array = np.asarray(output)
        if array.size == 1:
            return float(array.reshape(-1)[0])
    raise RuntimeError("could not identify classifier probability output")


class ModelRegistry:
    """Tenant-aware active model cache with global fallback."""

    def __init__(self) -> None:
        self._cache: dict[str, OnnxModel] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    async def get(self, tenant_id: str | None) -> OnnxModel | None:
        key = tenant_id or "global"
        if key in self._cache:
            return self._cache[key]
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            if key in self._cache:
                return self._cache[key]
            model = await self._load(tenant_id)
            if model is not None:
                self._cache[key] = model
            return model

    async def invalidate(self, tenant_id: str | None) -> None:
        self._cache.pop(tenant_id or "global", None)

    async def _load(self, tenant_id: str | None) -> OnnxModel | None:
        from cyclothone.storage.supabase_client import supabase

        async def _query():
            client = await supabase._ensure()
            query = client.table("models").select(
                "version,artifact_path,artifact_sha256,feature_names"
            ).eq("active", True)
            query = query.is_("tenant_id", "null") if tenant_id is None else query.eq("tenant_id", tenant_id)
            return await query.limit(1).execute()

        try:
            response = await supabase._retry(_query, attempts=2)
        except Exception as exc:
            logger.warning("model lookup failed: %s", exc)
            return None
        rows = response.data or []
        if not rows and tenant_id is not None:
            return await self._load(None)
        if not rows:
            return None
        row = rows[0]
        if row.get("feature_names") != FEATURE_NAMES:
            logger.error("rejecting model v%s: feature schema mismatch", row.get("version"))
            return None

        async def _download():
            client = await supabase._ensure()
            return await client.storage.from_("models").download(row["artifact_path"])

        try:
            data = await supabase._retry(_download, attempts=3)
            model = OnnxModel.from_bytes(data, int(row["version"]), row["artifact_sha256"])
        except Exception as exc:
            logger.error("model artifact rejected: %s", exc)
            return None
        logger.info("loaded model v%s for %s", row["version"], tenant_id or "global")
        return model


registry = ModelRegistry()
