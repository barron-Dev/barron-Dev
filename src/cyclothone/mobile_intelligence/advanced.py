from __future__ import annotations

import asyncio
import hashlib
import logging
import math
import os
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Callable, Iterable

from cyclothone.storage.supabase_client import supabase

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class Ss7Decision:
    gt: str
    opcode: str
    rate_per_second: float
    z_score: float
    action: str


class SS7Anomaly:
    def __init__(self, window_ms: int = 60_000) -> None:
        self.window_ms = window_ms
        self.win: dict[str, deque[int]] = defaultdict(deque)

    def observe(self, gt: str, opcode: str, timestamp_ms: int | None = None) -> Ss7Decision | None:
        now = timestamp_ms if timestamp_ms is not None else int(time.time() * 1000)
        key = f"{gt}:{opcode}"
        arr = self.win[key]
        arr.append(now)
        cutoff = now - self.window_ms
        while arr and arr[0] < cutoff:
            arr.popleft()

        burst_window_s = max((now - arr[0]) / 1000, 1.0) if arr else 1.0
        rate = len(arr) / min(self.window_ms / 1000, burst_window_s)
        mean = float(os.getenv("MDI_SS7_BASELINE_MEAN", "5"))
        sd = float(os.getenv("MDI_SS7_BASELINE_SD", "2"))
        z = (rate - mean) / sd if sd > 0 else 0.0
        if z > float(os.getenv("MDI_SS7_BLOCK_Z", "5")) and len(arr) > int(os.getenv("MDI_SS7_MIN_EVENTS", "100")):
            return Ss7Decision(gt, opcode, rate, z, "block_gt")
        return None


@dataclass(frozen=True, slots=True)
class OtpDecision:
    block: bool
    reason: str
    latency_ms: int


def detect_otp_relay(
    *,
    msisdn: str,
    imei: str,
    otp_issued_at_ms: int,
    otp_read_at_ms: int,
    carrier_mcc: str | None,
    ip_asn: str | None,
    previous_lat_lon: tuple[float, float] | None = None,
    current_lat_lon: tuple[float, float] | None = None,
    previous_at_ms: int | None = None,
) -> OtpDecision:
    latency = otp_read_at_ms - otp_issued_at_ms
    if latency < 800:
        return OtpDecision(True, "subsecond_read", latency)

    if ip_asn and "vpn" in ip_asn.lower() and carrier_mcc:
        return OtpDecision(True, "asn_carrier_mismatch", latency)

    if previous_lat_lon and current_lat_lon and previous_at_ms is not None:
        elapsed_min = max((otp_read_at_ms - previous_at_ms) / 60_000, 1e-6)
        distance = haversine_km(*previous_lat_lon, *current_lat_lon)
        if distance / elapsed_min > 800:
            return OtpDecision(True, "impossible_geographic_jump", latency)

    return OtpDecision(False, "ok", latency)


def flash_call_anomaly(
    calls: Iterable[dict[str, Any]],
    *,
    now_ms: int | None = None,
) -> list[dict[str, Any]]:
    now = now_ms if now_ms is not None else int(time.time() * 1000)
    by_source: dict[str, list[int]] = defaultdict(list)
    for call in calls:
        duration = int(call.get("durationMs") or 0)
        if 0 < duration < 900:
            by_source[str(call.get("from") or "")].append(int(call.get("at") or 0))

    out: list[dict[str, Any]] = []
    for source, times in by_source.items():
        burst = sum(1 for t in times if t > now - 180_000)
        if burst >= 5:
            out.append({"cluster": source, "risk": min(1.0, burst / 12)})
    return out


def trunk_fingerprint(sip_invite: dict[str, str]) -> str:
    parts = "|".join(
        sip_invite.get(k, "")
        for k in ("user-agent", "p-asserted-identity", "allow", "supported", "contact")
    )
    return hashlib.blake2b(parts.encode("utf-8"), digest_size=8).hexdigest()


def link_cross_border(
    events: Iterable[dict[str, Any]],
    window_ms: int = 6 * 3600_000,
) -> list[tuple[str, str, float]]:
    by_imei: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        imei = str(event.get("imei") or "")
        if imei:
            by_imei[imei].append(event)

    out: list[tuple[str, str, float]] = []
    for group in by_imei.values():
        group.sort(key=lambda x: int(x.get("at") or 0))
        for i, left in enumerate(group):
            for right in group[i + 1 :]:
                if left.get("country") == right.get("country"):
                    continue
                dt = abs(int(right.get("at") or 0) - int(left.get("at") or 0))
                if dt <= window_ms:
                    score = max(0.0, 1 - dt / window_ms)
                    out.append((str(left.get("subjectId")), str(right.get("subjectId")), score))
    return out


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0088
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


def footprint_radius_km(altitude_km: float, min_elevation_deg: float) -> float:
    earth = 6371.0088
    elevation = math.radians(max(0.1, min_elevation_deg))
    horizon = math.acos(min(earth / (earth + max(altitude_km, 1.0)), 1.0))
    return max(1.0, earth * max(0.0, horizon - elevation))


async def satellite_corroborate(
    claim: dict[str, Any],
    satellites: Iterable[dict[str, Any]],
    min_elevation_deg: float = 10,
) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for satellite in satellites:
        propagate: Callable[[float], dict[str, float]] | None = satellite.get("propagate")
        if propagate is None:
            continue
        position = propagate(float(claim["at"]))
        distance = haversine_km(
            float(position["lat"]),
            float(position["lon"]),
            float(claim["lat"]),
            float(claim["lon"]),
        )
        horizon = footprint_radius_km(float(position.get("altKm", 500.0)), min_elevation_deg)
        if distance <= horizon:
            elevation = max(0.0, 90.0 - distance / horizon * 90.0)
            hits.append({"noradId": int(satellite["noradId"]), "elevation": elevation})
    hits.sort(key=lambda x: x["elevation"], reverse=True)
    return hits


class AdvancedMdiService:
    def __init__(self) -> None:
        self.ss7 = SS7Anomaly()

    async def persist_alert(
        self,
        *,
        alert_type: str,
        subject_id: str | None,
        severity: str,
        score: float | None,
        action: str,
        algorithm: str,
        explanation: dict[str, Any],
        case_id: str | None = None,
        tenant_id: str,

    ) -> dict[str, Any]:
        row = await supabase.insert_one(
            "mdi_advanced_alerts",
            {
                "alert_type": alert_type,
                "subject_id": subject_id,
                "severity": severity,
                "score": score,
                "action": action,
                "algorithm": algorithm,
                "explanation": explanation,
                "case_id": case_id,
                "tenant_id": tenant_id,
            },
        )
        return dict(row)

    async def observe_ss7(self, gt: str, opcode: str, timestamp_ms: int | None = None, *, tenant_id: str) -> dict[str, Any]:
        decision = self.ss7.observe(gt, opcode, timestamp_ms)
        if decision is None:
            return {"detected": False}
        alert = await self.persist_alert(
            alert_type="ss7_map_anomaly",
            subject_id=None,
            severity="high",
            score=min(1.0, decision.z_score / 10),
            action=decision.action,
            algorithm="ss7_map_sliding_zscore_v1",
            tenant_id=tenant_id,
            explanation={
                "gt": decision.gt,
                "opcode": decision.opcode,
                "rate_per_second": decision.rate_per_second,
                "z_score": decision.z_score,
            },
        )
        return {"detected": True, "decision": decision.__dict__, "alert": alert}

    async def observe_otp(self, event: dict[str, Any], *, tenant_id: str) -> dict[str, Any]:
        decision = detect_otp_relay(**event)
        if not decision.block:
            return {"detected": False, "decision": decision.__dict__}
        alert = await self.persist_alert(
            alert_type="otp_relay",
            subject_id=None,
            severity="high",
            score=min(1.0, max(0.0, 1 - decision.latency_ms / 5000)),
            action="block_otp_route",
            algorithm="otp_relay_stream_v1",
            tenant_id=tenant_id,
            explanation={"reason": decision.reason, "latency_ms": decision.latency_ms},
        )
        return {"detected": True, "decision": decision.__dict__, "alert": alert}

    async def observe_flash_calls(self, calls: list[dict[str, Any]], *, tenant_id: str) -> dict[str, Any]:
        findings = flash_call_anomaly(calls)
        alerts = []
        for finding in findings:
            alerts.append(await self.persist_alert(
                alert_type="flash_call_burst",
                subject_id=None,
                severity="medium" if finding["risk"] < .75 else "high",
                score=float(finding["risk"]),
                action="review_otp_flash_call_route",
                algorithm="flash_call_burst_v1",
                tenant_id=tenant_id,
                explanation=finding,
            ))
        return {"detected": bool(alerts), "alerts": alerts}

    async def observe_sip(self, sip_invite: dict[str, str]) -> dict[str, Any]:
        fingerprint = trunk_fingerprint(sip_invite)
        return {"fingerprint": fingerprint}

    async def observe_cross_border(self, events: list[dict[str, Any]], *, tenant_id: str) -> dict[str, Any]:
        links = link_cross_border(events)
        alerts = []
        for left, right, score in links:
            alerts.append(await self.persist_alert(
                alert_type="cross_border_ring_link",
                subject_id=left,
                severity="high" if score >= .8 else "medium",
                score=score,
                action="correlate_investigation",
                algorithm="cross_border_imei_temporal_v1",
                tenant_id=tenant_id,
                explanation={"subject_a": left, "subject_b": right, "link_score": score},
            ))
        return {"detected": bool(alerts), "links": links, "alerts": alerts}


class AdvancedMdiScheduler:
    INTERVAL = 60

    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self._loop(), name="cyclothone-mdi-advanced")

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _loop(self) -> None:
        await asyncio.sleep(10)
        while not self._stop.is_set():
            try:
                await supabase.rpc("mdi_materialize_wangiri", {})
                await supabase.rpc("mdi_materialize_grey_routes", {})
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("mdi advanced materialization failed")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.INTERVAL)
            except asyncio.TimeoutError:
                pass
