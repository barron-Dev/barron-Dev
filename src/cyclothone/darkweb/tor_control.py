from __future__ import annotations

import ipaddress
import logging
import os
import re
import threading
import time
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)
_ONION_HOST = re.compile(r"^[a-z2-7]{56}\\.onion$", re.IGNORECASE)
_REQUIRED = (
    "route_verified",
    "hs_desc_content_received",
    "descriptor_fetched",
    "rendezvous_hop_verified",
    "stream_circuit_bound",
)


def _private_control_host(host: str) -> bool:
    value = host.strip().lower().rstrip(".")
    if value in {"localhost", "tor"} or value.endswith((".internal", ".local", ".railway.internal")):
        return True
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(address.is_loopback or address.is_private or address.is_link_local)


class TorControlProofCollector:
    """Collect per-request Tor control events without retaining descriptor bodies.

    Requires an authenticated local/private Tor ControlPort. SOCKS reachability,
    bootstrap status, or a descriptor event alone never proves a checked page.
    """

    def __init__(self, request_id: str, *, host: str, port: int, password: str | None = None,
                 cookie_path: str | None = None, descriptor_timeout: float = 25.0) -> None:
        self.request_id = str(request_id)
        self.host = host
        self.port = int(port)
        self.password = password
        self.cookie_path = cookie_path
        self.descriptor_timeout = max(1.0, min(float(descriptor_timeout), 60.0))
        self.controller = None
        self.bootstrapped = False
        self.tor_version: str | None = None
        self._lock = threading.RLock()
        self._starts: dict[str, float] = {}
        self._descriptor_events: dict[str, list[tuple[float, str, bool]]] = {}
        self._streams: list[tuple[float, str, str, str]] = []
        self._circuits: list[tuple[float, str, str, str]] = []
        self._closed = False

    @classmethod
    def enabled_from_env(cls) -> bool:
        return os.getenv("CYCLOTHONE_DW_TOR_CONTROL_ENABLED", "").strip().lower() in {"1", "true", "yes", "on"}

    @classmethod
    def from_env(cls, request_id: str) -> "TorControlProofCollector":
        host = os.getenv("CYCLOTHONE_DW_TOR_CONTROL_HOST", "127.0.0.1").strip()
        if not _private_control_host(host):
            raise RuntimeError("tor_control_host_must_be_private")
        return cls(
            request_id,
            host=host,
            port=int(os.getenv("CYCLOTHONE_DW_TOR_CONTROL_PORT", "9051")),
            password=os.getenv("CYCLOTHONE_DW_TOR_CONTROL_PASSWORD") or None,
            cookie_path=os.getenv("CYCLOTHONE_DW_TOR_CONTROL_COOKIE") or None,
            descriptor_timeout=float(os.getenv("CYCLOTHONE_DW_TOR_DESCRIPTOR_TIMEOUT_SECONDS", "25")),
        )

    def start(self) -> None:
        if self.controller is not None:
            return
        try:
            from stem.control import Controller, EventType
        except ImportError as exc:
            raise RuntimeError("tor_control_stem_dependency_missing") from exc
        controller = Controller.from_port(address=self.host, port=self.port)
        controller.set_socket_timeout(5.0)
        try:
            if self.cookie_path:
                controller.authenticate(cookie_path=self.cookie_path)
            elif self.password:
                controller.authenticate(password=self.password)
            else:
                controller.authenticate()
            self.tor_version = str(controller.get_version())
            bootstrap = str(controller.get_info("status/bootstrap-phase", ""))
            self.bootstrapped = bool(re.search(r"(?:^|\\s)PROGRESS=100(?:\\s|$)", bootstrap))
            controller.add_event_listener(self._on_hs_desc, EventType.HS_DESC)
            controller.add_event_listener(self._on_hs_desc_content, EventType.HS_DESC_CONTENT)
            controller.add_event_listener(self._on_stream, EventType.STREAM)
            controller.add_event_listener(self._on_circuit, EventType.CIRC)
            self.controller = controller
        except Exception:
            controller.close()
            raise

    @staticmethod
    def _host_from_event(event: object) -> str:
        raw = str(getattr(event, "address", "") or "").strip().lower().rstrip(".")
        if _ONION_HOST.fullmatch(raw):
            return raw
        target = str(getattr(event, "target_address", "") or getattr(event, "target", "") or "").strip()
        if target.startswith("[") and "]" in target:
            target = target[1:target.index("]")]
        elif target.count(":") == 1:
            target = target.rsplit(":", 1)[0]
        target = target.lower().rstrip(".")
        return target if _ONION_HOST.fullmatch(target) else ""

    def _on_hs_desc(self, event: object) -> None:
        host = self._host_from_event(event)
        if not host:
            return
        action = str(getattr(event, "action", "") or "").upper()
        descriptor_id = str(getattr(event, "descriptor_id", "") or "")
        with self._lock:
            self._descriptor_events.setdefault(host, []).append(
                (time.monotonic(), action, bool(descriptor_id))
            )

    def _on_hs_desc_content(self, event: object) -> None:
        host = self._host_from_event(event)
        if not host:
            return
        descriptor = getattr(event, "descriptor", None)
        with self._lock:
            self._descriptor_events.setdefault(host, []).append(
                (time.monotonic(), "CONTENT", isinstance(descriptor, str) and bool(descriptor.strip()))
            )

    def _on_stream(self, event: object) -> None:
        host = self._host_from_event(event)
        if not host:
            return
        with self._lock:
            self._streams.append((
                time.monotonic(),
                host,
                str(getattr(event, "status", "") or "").upper(),
                str(getattr(event, "circ_id", "") or ""),
            ))

    def _on_circuit(self, event: object) -> None:
        with self._lock:
            self._circuits.append((
                time.monotonic(),
                str(getattr(event, "id", "") or ""),
                str(getattr(event, "status", "") or "").upper(),
                str(getattr(event, "purpose", "") or "").upper(),
            ))

    def begin_seed(self, seed_url: str) -> None:
        parsed = urlsplit(seed_url)
        host = (parsed.hostname or "").lower()
        if not _ONION_HOST.fullmatch(host):
            raise ValueError("tor_control_invalid_onion_host")
        started = time.monotonic()
        with self._lock:
            self._starts[host] = started
        if self.controller is None:
            return
        # HSFETCH is a read-only Tor control command. The descriptor body is
        # consumed only as a Boolean proof and is never written to logs/storage.
        try:
            reply = self.controller.msg(f"HSFETCH {host[:-6]}")
            if not reply.is_ok():
                logger.info("Tor HSFETCH was rejected for a configured seed")
        except Exception as exc:
            logger.info("Tor HSFETCH command failed error=%s", type(exc).__name__)

    def proof_for(self, seed_url: str, content_sha256: str) -> dict[str, object]:
        parsed = urlsplit(seed_url)
        host = (parsed.hostname or "").lower()
        started = self._starts.get(host, float("inf"))
        with self._lock:
            descriptor_events = [
                item for item in self._descriptor_events.get(host, []) if item[0] >= started
            ]
            streams = [
                item for item in self._streams
                if item[0] >= started and item[1] == host and item[2] == "SUCCEEDED" and item[3] not in {"", "0"}
            ]
            circuits = [
                item for item in self._circuits
                if item[0] >= started and item[2] == "BUILT" and item[3] in {"HS_CLIENT_REND", "HS_CLIENT_REND_JOINED"}
            ]
        descriptor_fetched = any(action == "RECEIVED" and has_id for _, action, has_id in descriptor_events)
        content_received = any(action == "CONTENT" and has_content for _, action, has_content in descriptor_events)
        built_circuit_ids = {circ_id for _, circ_id, _, _ in circuits}
        bound_stream = next((stream for stream in streams if stream[3] in built_circuit_ids), None)
        rendezvous_verified = bound_stream is not None
        route_verified = bool(self.bootstrapped and bound_stream is not None)
        return {
            "service_request_id": self.request_id,
            "content_sha256": str(content_sha256).lower(),
            "tor_control_authenticated": self.controller is not None,
            "tor_bootstrap_complete": self.bootstrapped,
            "tor_version": self.tor_version,
            "route_verified": route_verified,
            "hs_desc_content_received": content_received,
            "descriptor_fetched": descriptor_fetched,
            "rendezvous_hop_verified": rendezvous_verified,
            "stream_circuit_bound": bound_stream is not None,
            "descriptor_event_count": len(descriptor_events),
            "stream_circuit_id": bound_stream[3] if bound_stream else None,
        }

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        controller, self.controller = self.controller, None
        if controller is not None:
            try:
                for event_type, listener in (
                    ("HS_DESC", self._on_hs_desc),
                    ("HS_DESC_CONTENT", self._on_hs_desc_content),
                    ("STREAM", self._on_stream),
                    ("CIRC", self._on_circuit),
                ):
                    try:
                        from stem.control import EventType
                        controller.remove_event_listener(listener)
                    except Exception:
                        break
                controller.close()
            except Exception:
                logger.info("Tor control connection close failed")
