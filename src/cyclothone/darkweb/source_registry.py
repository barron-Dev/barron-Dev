"""Cyclothone public-source registry and conservative Telegram discovery.

Only public Telegram preview pages are fetched. This module never joins channels,
uses account pools, contacts users, accesses private/invite-only content, or stores
raw credential material. Newly discovered candidates remain quarantined for 7 days.
"""
from __future__ import annotations

import asyncio
import hashlib
import html
import logging
import re
from datetime import UTC, datetime, timedelta

import httpx

from cyclothone.darkweb.telegram_config import configured_telegram_channels
from cyclothone.storage.supabase_client import supabase

logger = logging.getLogger(__name__)
QUARANTINE_DAYS = 7
DEFAULT_DISCOVERY_BATCH = 250
DEFAULT_MONITOR_BATCH = 100
TELEGRAM_LINK_RE = re.compile(r"(?i)(?:https?://)?(?:www\.)?(?:t\.me|telegram\.me)/([a-z0-9_]{5,32})(?:[/?#][^\s\"'<>]*)?")
MENTION_RE = re.compile(r"(?<![a-zA-Z0-9_])@([a-zA-Z0-9_]{5,32})")
DATE_RE = re.compile(r'datetime="([^"]+)"')
MESSAGE_RE = re.compile(r'tgme_widget_message_wrap')
SKIP_HANDLES = {
    "share", "addstickers", "addemoji", "proxy", "s", "joinchat", "iv",
    "login", "faq", "apps", "blog", "telegram", "contact", "privacy",
    "setlanguage", "boost", "premium", "giftcode", "business",
}


def clean_handle(value: str) -> str | None:
    value = value.strip().lstrip("@").lower()
    if not re.fullmatch(r"[a-z0-9_]{5,32}", value) or value in SKIP_HANDLES:
        return None
    return value


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def extract_candidates(page: str, parent: str) -> list[dict]:
    """Extract public Telegram channel links/mentions; never fetch arbitrary URLs."""
    decoded = html.unescape(page)
    candidates: dict[str, dict] = {}
    for match in TELEGRAM_LINK_RE.finditer(decoded):
        handle = clean_handle(match.group(1))
        if not handle or handle == parent.lower():
            continue
        context = decoded[max(0, match.start() - 180):match.end() + 80].lower()
        method = "forward" if "forwarded" in context or "forward" in context else "link"
        candidates.setdefault(handle, {
            "identity": handle, "source_type": "telegram", "display_name": handle,
            "discovered_by": method, "parent_identity": parent.lower(),
            "source_url": f"https://t.me/{handle}", "channel_status": None,
            "monitoring_status": "QUARANTINED",
            "metadata": {"discovery_method": method, "parent": parent.lower()},
        })
    text_only = re.sub(r"<[^>]+>", " ", decoded)
    for match in MENTION_RE.finditer(text_only):
        handle = clean_handle(match.group(1))
        if not handle or handle == parent.lower():
            continue
        candidates.setdefault(handle, {
            "identity": handle, "source_type": "telegram", "display_name": handle,
            "discovered_by": "snowball", "parent_identity": parent.lower(),
            "source_url": f"https://t.me/{handle}", "channel_status": None,
            "monitoring_status": "QUARANTINED",
            "metadata": {"discovery_method": "public_mention", "parent": parent.lower()},
        })
    return list(candidates.values())


def validation_signals(page: str, connected_links: int = 0) -> tuple[int, list[str], int]:
    """Score only observable public evidence; unknown signals never earn points."""
    decoded = html.unescape(re.sub(r"<[^>]+>", " ", page))
    dates = []
    for raw in DATE_RE.findall(page):
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            dates.append(parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed)
        except ValueError:
            continue
    signals: list[str] = []
    if len(set(TELEGRAM_LINK_RE.findall(page))) >= 2:
        signals.append("cross_channel_references")
    if dates and min(dates).astimezone(UTC) <= datetime.now(UTC) - timedelta(days=30):
        signals.append("history_at_least_30_days")
    messages = len(MESSAGE_RE.findall(page))
    if messages >= 10:
        signals.append("public_message_volume")
    if len(decoded.strip()) >= 1500:
        signals.append("substantive_public_content")
    if dates and max(dates).astimezone(UTC) >= datetime.now(UTC) - timedelta(days=7):
        signals.append("recent_activity")
    if connected_links >= 2:
        signals.append("connected_link_network")
    if len(set(TELEGRAM_LINK_RE.findall(page))) >= 1:
        signals.append("public_related_channel")
    return min(10, len(signals)), signals, messages


def classify_public_http_response(status_code: int, body: str) -> tuple[str | None, str]:
    """Separate confirmed public-page states from inconclusive HTTP outcomes."""
    if status_code in (401, 403):
        return "PRIVATE", "access_restricted"
    if status_code == 404:
        return "EXPIRED", "not_found"
    if 200 <= status_code < 300:
        if body.strip():
            return "ONLINE", "checked"
        return None, "empty_response"
    if 300 <= status_code < 400:
        return None, "redirect_not_followed"
    if status_code == 429:
        return None, "rate_limited"
    if status_code >= 500:
        return None, "provider_error"
    return None, "unexpected_http_status"


def merge_validation_metadata(existing: dict | None, signals: list[str]) -> dict:
    """Add current validation signals without destroying source provenance."""
    merged = dict(existing) if isinstance(existing, dict) else {}
    merged["validation_signals"] = list(signals)
    return merged


def classify_validation(score: int) -> str | None:
    """Return a validation tier only when enough positive evidence exists.

    A low/empty page is unknown, not proof of fraud. SCAM requires separate,
    affirmative fraud signals and is intentionally never inferred from absence.
    """
    if score >= 8:
        return "HIGH"
    if score >= 5:
        return "MEDIUM"
    if score >= 3:
        return "LOW"
    return None


class TelegramSourceRegistry:
    def __init__(self) -> None:
        self._client_cache = None

    async def client(self):
        if self._client_cache is None:
            self._client_cache = await supabase._ensure()
        return self._client_cache

    async def event(self, identity: str, event_type: str, details: dict, source_id: str | None = None) -> None:
        payload = {"identity": identity.lower(), "event_type": event_type, "details": details}
        if source_id:
            payload["source_id"] = source_id
        try:
            client = await self.client()
            await supabase._retry(lambda: client.table("source_registry_events").insert(payload).execute(), attempts=1)
        except Exception:
            logger.warning("source registry event append failed identity=%s type=%s", identity, event_type, exc_info=True)

    async def seed(self, handles: list[str]) -> None:
        handles = list(dict.fromkeys(h for raw in handles if (h := clean_handle(raw))))
        if not handles:
            return
        client = await self.client()
        existing_response = await supabase._retry(
            lambda: client.table("source_registry").select("identity").in_("identity", handles).execute(),
            attempts=1,
        )
        existing = {str(row.get("identity", "")).lower() for row in (existing_response.data or [])}
        now = datetime.now(UTC).isoformat()
        payloads = [{
            "identity": handle, "source_type": "telegram", "display_name": handle,
            "discovered_by": "seed", "source_url": f"https://t.me/{handle}",
            "monitoring_status": "ACTIVE", "channel_status": None,
            "first_seen": now, "last_seen": now,
            "metadata": {"seed_source": "CYCLOTHONE_DW_TELEGRAM_CHANNELS"},
        } for handle in handles if handle not in existing]
        if not payloads:
            return
        response = await supabase._retry(lambda: client.table("source_registry").insert(payloads).execute(), attempts=1)
        for row in (response.data or []):
            await self.event(str(row["identity"]), "seed_registered", {"source_type": "telegram"}, str(row["id"]))

    async def active_channels(self, limit: int = DEFAULT_MONITOR_BATCH) -> list[str]:
        client = await self.client()
        response = await supabase._retry(
            lambda: client.table("source_registry").select("identity")
                .eq("source_type", "telegram").eq("monitoring_status", "ACTIVE")
                .order("last_checked", desc=False, nullsfirst=True)
                .limit(max(1, min(limit, 1000))).execute(),
            attempts=1,
        )
        return list(dict.fromkeys(
            str(row["identity"]).lower() for row in (response.data or [])
            if clean_handle(str(row.get("identity") or ""))
        ))

    async def mark_checked(self, statuses: dict[str, str]) -> None:
        if not statuses:
            return
        client = await self.client()
        now = datetime.now(UTC).isoformat()
        for identity, raw_status in statuses.items():
            channel_status = "ONLINE" if raw_status == "checked" else "OFFLINE"
            try:
                updates = {"last_checked": now, "channel_status": channel_status, "updated_at": now}
                if channel_status == "ONLINE":
                    updates["last_seen"] = now
                await supabase._retry(
                    lambda i=identity, payload=updates: client.table("source_registry").update(payload).eq("identity", i.lower()).execute(),
                    attempts=1,
                )
            except Exception:
                logger.warning("source registry status update failed identity=%s", identity, exc_info=True)

    async def tick(self, max_sources: int = DEFAULT_DISCOVERY_BATCH) -> dict:
        await self.seed(configured_telegram_channels())
        client = await self.client()
        response = await supabase._retry(
            lambda: client.table("source_registry")
                .select("id,identity,last_seen,metadata").eq("source_type", "telegram")
                .eq("monitoring_status", "ACTIVE")
                .order("last_checked", desc=False, nullsfirst=True)
                .limit(max(1, min(max_sources, 2000))).execute(),
            attempts=1,
        )
        active = response.data or []
        discovered = checked = promoted = excluded = 0
        async with httpx.AsyncClient(
            timeout=12.0, follow_redirects=False,
            headers={"user-agent": "CyclothonePublicExposureMonitor/1.0"},
        ) as http:
            for row in active:
                identity = str(row.get("identity") or "").lower()
                if not clean_handle(identity):
                    continue
                now = datetime.now(UTC).isoformat()
                try:
                    page_response = await http.get(f"https://t.me/s/{identity}")
                    page = page_response.text if 200 <= page_response.status_code < 300 else ""
                    status, outcome = classify_public_http_response(page_response.status_code, page)
                    metadata = dict(row.get("metadata") or {})
                    metadata["last_check_outcome"] = outcome
                    updates = {
                        "last_checked": now, "updated_at": now, "metadata": metadata,
                    }
                    if status is not None:
                        updates["channel_status"] = status
                    if status == "ONLINE":
                        updates["last_seen"] = now
                    await supabase._retry(
                        lambda i=identity, payload=updates: client.table("source_registry").update(payload).eq("identity", i).execute(),
                        attempts=1,
                    )
                    checked += 1
                    if status != "ONLINE":
                        await self.event(identity, "public_source_check", {"outcome": outcome, "http_status": page_response.status_code}, str(row.get("id") or "") or None)
                        continue
                    candidates = extract_candidates(page, identity)
                    if candidates:
                        candidate_ids = [candidate["identity"] for candidate in candidates]
                        known_response = await supabase._retry(
                            lambda ids=candidate_ids: client.table("source_registry").select("identity").in_("identity", ids).execute(),
                            attempts=1,
                        )
                        known = {str(item.get("identity", "")).lower() for item in (known_response.data or [])}
                        fresh = [item for item in candidates if item["identity"] not in known]
                        if fresh:
                            inserted = await supabase._retry(lambda batch=fresh: client.table("source_registry").insert(batch).execute(), attempts=1)
                            for candidate in (inserted.data or []):
                                discovered += 1
                                await self.event(str(candidate["identity"]), "candidate_quarantined", {
                                    "discovered_by": candidate["discovered_by"],
                                    "parent_identity": identity,
                                    "quarantine_days": QUARANTINE_DAYS,
                                }, str(candidate["id"]))
                                edge_type = candidate["discovered_by"] if candidate["discovered_by"] in {"link", "forward"} else "mention"
                                try:
                                    await supabase._retry(lambda c=candidate, p=row: client.table("source_registry_edges").insert({
                                        "source_id": p["id"], "target_id": c["id"], "edge_type": edge_type,
                                        "metadata": {"discovery_method": c["discovered_by"]},
                                    }).execute(), attempts=1)
                                except Exception:
                                    logger.debug("source registry edge write failed", exc_info=True)
                    score, signals, message_count = validation_signals(page, connected_links=len(candidates))
                    validation = classify_validation(score)
                    metadata = merge_validation_metadata(row.get("metadata"), signals)
                    await supabase._retry(lambda i=identity, sc=score, sig=signals, mc=message_count, v=validation, md=metadata: client.table("source_registry").update({
                        "validation_score": sc, "validation_status": v, "message_count": mc,
                        "metadata": md, "last_seen": now,
                    }).eq("identity", i).execute(), attempts=1)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.warning("telegram discovery failed identity=%s error=%s", identity, type(exc).__name__)
                # Respectful pacing; no proxy rotation or detection evasion.
                await asyncio.sleep(2.0)

        cutoff = (datetime.now(UTC) - timedelta(days=QUARANTINE_DAYS)).isoformat()
        quarantined = await supabase._retry(
            lambda: client.table("source_registry")
                .select("id,identity,validation_score,metadata").eq("monitoring_status", "QUARANTINED")
                .lte("first_seen", cutoff).execute(),
            attempts=1,
        )
        for candidate in (quarantined.data or []):
            # Quarantined candidates are checked only after the full seven-day hold.
            # Missing scores are never treated as clean or promoted automatically.
            if candidate.get("validation_score") is None:
                identity = str(candidate.get("identity") or "").lower()
                try:
                    async with httpx.AsyncClient(timeout=12.0, follow_redirects=False, headers={"user-agent": "CyclothonePublicExposureMonitor/1.0"}) as http:
                        check = await http.get(f"https://t.me/s/{identity}")
                    check_page = check.text if 200 <= check.status_code < 300 else ""
                    check_status, outcome = classify_public_http_response(check.status_code, check_page)
                    if check_status in {"EXPIRED", "PRIVATE"}:
                        new_state = "EXPIRED" if check_status == "EXPIRED" else "EXCLUDED"
                        await supabase._retry(lambda c=candidate, cs=check_status, ns=new_state, out=outcome: client.table("source_registry").update({
                            "channel_status": cs, "monitoring_status": ns,
                            "last_checked": datetime.now(UTC).isoformat(),
                        }).eq("id", c["id"]).eq("monitoring_status", "QUARANTINED").execute(), attempts=1)
                        await self.event(identity, "quarantined_source_terminal_state", {"channel_status": check_status, "outcome": outcome}, str(candidate["id"]))
                        excluded += int(new_state == "EXCLUDED")
                        continue
                    if check_status != "ONLINE":
                        metadata = merge_validation_metadata(candidate.get("metadata"), [])
                        metadata["last_check_outcome"] = outcome
                        await supabase._retry(lambda c=candidate, md=metadata: client.table("source_registry").update({
                            "metadata": md, "last_checked": datetime.now(UTC).isoformat(),
                        }).eq("id", c["id"]).eq("monitoring_status", "QUARANTINED").execute(), attempts=1)
                        await self.event(identity, "quarantined_source_check_inconclusive", {"outcome": outcome, "http_status": check.status_code}, str(candidate["id"]))
                        continue
                    related_candidates = extract_candidates(check_page, identity)
                    score, signals, message_count = validation_signals(check_page, connected_links=len(related_candidates))
                    validation = classify_validation(score)
                    metadata = merge_validation_metadata(candidate.get("metadata"), signals)
                    await supabase._retry(lambda c=candidate, sc=score, sig=signals, mc=message_count, v=validation, md=metadata: client.table("source_registry").update({
                        "channel_status": "ONLINE", "validation_score": sc, "validation_status": v,
                        "message_count": mc, "metadata": md,
                        "last_checked": datetime.now(UTC).isoformat(), "last_seen": datetime.now(UTC).isoformat(),
                    }).eq("id", c["id"]).eq("monitoring_status", "QUARANTINED").execute(), attempts=1)
                    candidate["validation_score"] = score
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.warning("quarantine validation failed identity=%s error=%s", identity, type(exc).__name__)
                    continue
                await asyncio.sleep(2.0)
            score = candidate.get("validation_score")
            new_status = "ACTIVE" if score is not None and int(score) >= 5 else "EXCLUDED" if score is not None and int(score) <= 2 else None
            if not new_status:
                continue
            await supabase._retry(lambda c=candidate, state=new_status: client.table("source_registry").update({
                "monitoring_status": state, "updated_at": datetime.now(UTC).isoformat(),
            }).eq("id", c["id"]).eq("monitoring_status", "QUARANTINED").execute(), attempts=1)
            await self.event(str(candidate["identity"]), "quarantine_resolved", {
                "monitoring_status": new_status, "validation_score": score,
            }, str(candidate["id"]))
            promoted += int(new_status == "ACTIVE")
            excluded += int(new_status == "EXCLUDED")

        total = await supabase._retry(lambda: client.table("source_registry").select("id", count="exact").execute(), attempts=1)
        active_count = await supabase._retry(lambda: client.table("source_registry").select("id", count="exact").eq("monitoring_status", "ACTIVE").execute(), attempts=1)
        result = {
            "active_checked": checked, "discovered": discovered, "promoted": promoted,
            "excluded": excluded, "active_registry_count": int(getattr(active_count, "count", None) or len(active_count.data or [])),
            "registry_total": int(getattr(total, "count", None) or len(total.data or [])),
        }
        logger.info("dark web registry tick %s", result)
        return result


async def run_discovery_tick() -> dict:
    try:
        return await TelegramSourceRegistry().tick()
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.exception("dark web source registry tick failed")
        return {"status": "failed", "reason": "registry_tick_failed"}


async def active_telegram_channels(limit: int = DEFAULT_MONITOR_BATCH) -> list[str]:
    try:
        return await TelegramSourceRegistry().active_channels(limit)
    except Exception:
        logger.exception("unable to load active Telegram registry channels")
        return []


async def record_telegram_checks(statuses: dict[str, str]) -> None:
    await TelegramSourceRegistry().mark_checked(statuses)
