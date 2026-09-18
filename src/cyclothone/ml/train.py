from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import numpy as np
from lightgbm import LGBMClassifier
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split

from sentinel.ml.features import FEATURE_NAMES, extract

logger = logging.getLogger(__name__)
MIN_SAMPLES = 200
MIN_POSITIVES = 20
MIN_NEGATIVES = 50


class NotEnoughData(Exception):
    pass


def _client():
    from sentinel.storage.supabase_client import supabase
    return supabase


async def _load_labeled_events(tenant_id: UUID | None, limit: int = 50_000) -> list[dict[str, Any]]:
    async def _do():
        client = await _client()._ensure()
        query = client.table("labels").select(
            "event_id,label,confidence,events!inner(id,event_type,payload)"
        )
        if tenant_id is not None:
            query = query.eq("tenant_id", str(tenant_id))
        return await query.limit(limit).execute()

    response = await _client()._retry(_do, attempts=3)
    return list(response.data or [])


def _build_matrix(rows: list[dict[str, Any]]) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    X: list[np.ndarray] = []
    y: list[int] = []
    weights: list[float] = []
    for row in rows:
        event = row.get("events") or {}
        X.append(extract(event.get("event_type", ""), event.get("payload") or {}))
        y.append(int(row["label"]))
        weights.append(float(row.get("confidence") or 1.0))
    return (
        np.vstack(X) if X else np.zeros((0, len(FEATURE_NAMES)), dtype=np.float32),
        np.asarray(y, dtype=np.int32),
        np.asarray(weights, dtype=np.float32),
    )


def train_model(X: np.ndarray, y: np.ndarray, sample_weight: np.ndarray) -> tuple[LGBMClassifier, dict[str, float]]:
    if len(y) < MIN_SAMPLES:
        raise NotEnoughData(f"need >= {MIN_SAMPLES} samples, have {len(y)}")
    positives = int(y.sum())
    negatives = int(len(y) - positives)
    if positives < MIN_POSITIVES:
        raise NotEnoughData(f"need >= {MIN_POSITIVES} positives, have {positives}")
    if negatives < MIN_NEGATIVES:
        raise NotEnoughData(f"need >= {MIN_NEGATIVES} negatives, have {negatives}")

    X_train, X_test, y_train, y_test, w_train, _ = train_test_split(
        X, y, sample_weight, test_size=0.2, random_state=42, stratify=y,
    )
    clf = LGBMClassifier(
        n_estimators=200,
        max_depth=4,
        learning_rate=0.05,
        subsample=0.9,
        random_state=42,
        verbose=-1,
    )
    clf.fit(X_train, y_train, sample_weight=w_train)
    probability = clf.predict_proba(X_test)[:, 1]
    prediction = (probability >= 0.5).astype(np.int32)
    metrics = {
        "auc": float(roc_auc_score(y_test, probability)) if len(set(y_test)) > 1 else 0.0,
        "avg_precision": float(average_precision_score(y_test, probability)),
        "precision": float(precision_score(y_test, prediction, zero_division=0)),
        "recall": float(recall_score(y_test, prediction, zero_division=0)),
        "f1": float(f1_score(y_test, prediction, zero_division=0)),
        "n_train": float(len(y_train)), "n_test": float(len(y_test)),
    }
    return clf, metrics


def export_onnx(clf: LGBMClassifier) -> bytes:
    from onnxmltools.convert import convert_lightgbm
    from onnxmltools.convert.common.data_types import FloatTensorType

    onnx_model = convert_lightgbm(
        clf,
        initial_types=[("input", FloatTensorType([None, len(FEATURE_NAMES)]))],
        target_opset=15,
    )
    return onnx_model.SerializeToString()


def _artifact_path(tenant_id: UUID | None, version: int) -> str:
    prefix = f"tenant/{tenant_id}" if tenant_id else "global"
    return f"{prefix}/v{version}/model.onnx"


async def _next_version(tenant_id: UUID | None) -> int:
    async def _do():
        client = await _client()._ensure()
        query = client.table("models").select("version")
        query = query.is_("tenant_id", "null") if tenant_id is None else query.eq("tenant_id", str(tenant_id))
        return await query.order("version", desc=True).limit(1).execute()
    response = await _client()._retry(_do)
    rows = response.data or []
    return int(rows[0]["version"]) + 1 if rows else 1


async def _upload_artifact(path: str, data: bytes) -> None:
    async def _do():
        client = await _client()._ensure()
        return await client.storage.from_("models").upload(
            path, data, {"content-type": "application/octet-stream", "upsert": "false"},
        )
    await _client()._retry(_do, attempts=3)


async def run_training(tenant_id: UUID | None) -> dict[str, Any]:
    started = datetime.now(timezone.utc)

    async def _create_run():
        client = await _client()._ensure()
        return await client.table("training_runs").insert({
            "tenant_id": str(tenant_id) if tenant_id else None,
            "status": "running", "algorithm": "gbdt",
            "hyperparams": {"n_estimators": 200, "max_depth": 4, "learning_rate": 0.05},
            "started_at": started.isoformat(),
        }).execute()

    run_response = await _client()._retry(_create_run)
    run_id = (run_response.data or [{}])[0].get("id")
    if not run_id:
        raise RuntimeError("training run could not be created")

    try:
        rows = await _load_labeled_events(tenant_id)
        X, y, weights = _build_matrix(rows)
        clf, metrics = train_model(X, y, weights)
        artifact = export_onnx(clf)
        sha256 = hashlib.sha256(artifact).hexdigest()
        version = await _next_version(tenant_id)
        path = _artifact_path(tenant_id, version)
        await _upload_artifact(path, artifact)

        async def _finalize():
            client = await _client()._ensure()
            return await client.table("training_runs").update({
                "status": "success", "n_samples": len(y), "n_positive": int(y.sum()),
                "n_negative": int(len(y) - y.sum()), "metrics": metrics,
                "artifact_path": path, "ended_at": datetime.now(timezone.utc).isoformat(),
            }).eq("id", run_id).execute()
        await _client()._retry(_finalize)

        async def _register():
            client = await _client()._ensure()
            return await client.table("models").insert({
                "tenant_id": str(tenant_id) if tenant_id else None,
                "version": version, "algorithm": "gbdt", "artifact_path": path,
                "artifact_sha256": sha256, "training_run_id": run_id,
                "metrics": metrics, "feature_names": FEATURE_NAMES, "active": False,
            }).execute()
        await _client()._retry(_register)
        return {"run_id": run_id, "version": version, "metrics": metrics,
                "artifact_path": path, "sha256": sha256}
    except Exception as exc:
        logger.exception("training run %s failed", run_id)
        async def _fail():
            client = await _client()._ensure()
            return await client.table("training_runs").update({
                "status": "failed", "error": str(exc)[:1000],
                "ended_at": datetime.now(timezone.utc).isoformat(),
            }).eq("id", run_id).execute()
        try:
            await _client()._retry(_fail, attempts=2)
        except Exception:
            logger.exception("failed to record training failure %s", run_id)
        raise
