from __future__ import annotations

import logging
import os
from datetime import UTC, datetime

from cryptography.fernet import Fernet, InvalidToken

from cyclothone.attribution.alerts import deliver_signed_webhook_async
from cyclothone.storage.supabase_client import supabase

logger = logging.getLogger(__name__)


def _fernet() -> Fernet:
    key = (os.getenv("CYCLOTHONE_WEBHOOK_ENCRYPTION_KEY") or "").strip()
    if not key:
        raise RuntimeError("webhook_encryption_not_configured")
    try:
        return Fernet(key.encode())
    except (ValueError, TypeError) as exc:
        raise RuntimeError("webhook_encryption_key_invalid") from exc


async def dispatch_pending_attribution_alerts(limit: int = 25) -> int:
    client = await supabase._ensure()
    alerts = await client.table("dw_attribution_alert_outbox").select(
        "alert_id,tenant_id,assessment_id,event_type,payload,attempts"
    ).is_("dispatched_at", "null").order("created_at").limit(max(1, min(100, limit))).execute()
    delivered_count = 0
    for alert in (alerts.data or []):
        tenant_id, alert_id = str(alert["tenant_id"]), str(alert["alert_id"])
        hooks_result = await client.table("dw_attribution_webhooks").select(
            "webhook_id,endpoint_url,secret_ciphertext,event_types,enabled"
        ).eq("tenant_id", tenant_id).eq("enabled", True).execute()
        hooks = [h for h in (hooks_result.data or []) if alert["event_type"] in (h.get("event_types") or [])]
        if not hooks:
            # No configured destination is a completed routing decision, not a fake delivery.
            await client.table("dw_attribution_alert_outbox").update({
                "dispatched_at": datetime.now(UTC).isoformat(), "attempts": int(alert.get("attempts") or 0) + 1,
                "last_error_code": "no_matching_webhook",
            }).eq("alert_id", alert_id).is_("dispatched_at", "null").execute()
            continue
        all_terminal = True
        for hook in hooks:
            previous = await client.table("dw_attribution_webhook_deliveries").select(
                "delivery_id,status,attempts"
            ).eq("alert_id", alert_id).eq("webhook_id", str(hook["webhook_id"])).limit(1).execute()
            prior = (previous.data or [{}])[0]
            if prior.get("status") == "delivered" or (prior.get("status") == "permanent_failure"):
                continue
            try:
                secret = _fernet().decrypt(str(hook["secret_ciphertext"]).encode())
                outcome = await deliver_signed_webhook_async(str(hook["endpoint_url"]), secret, dict(alert["payload"]))
            except (InvalidToken, RuntimeError, ValueError) as exc:
                outcome = {"status": "retryable_failure", "error_type": type(exc).__name__}
            status = outcome["status"]
            attempts = int(prior.get("attempts") or 0) + 1
            if status == "retryable_failure" and attempts < 8:
                all_terminal = False
            await client.table("dw_attribution_webhook_deliveries").upsert({
                "alert_id": alert_id, "webhook_id": str(hook["webhook_id"]),
                "status": status if status != "retryable_failure" or attempts < 8 else "permanent_failure",
                "http_status": outcome.get("http_status"), "error_code": outcome.get("error_type"),
                "attempts": attempts,
            }, on_conflict="alert_id,webhook_id").execute()
            if status == "delivered":
                delivered_count += 1
                await client.table("dw_attribution_webhooks").update({
                    "last_delivery_at": datetime.now(UTC).isoformat()
                }).eq("webhook_id", str(hook["webhook_id"])).execute()
        if all_terminal:
            await client.table("dw_attribution_alert_outbox").update({
                "dispatched_at": datetime.now(UTC).isoformat(), "attempts": int(alert.get("attempts") or 0) + 1,
                "last_error_code": None,
            }).eq("alert_id", alert_id).is_("dispatched_at", "null").execute()
        else:
            await client.table("dw_attribution_alert_outbox").update({
                "attempts": int(alert.get("attempts") or 0) + 1, "last_error_code": "delivery_pending",
            }).eq("alert_id", alert_id).is_("dispatched_at", "null").execute()
    return delivered_count
