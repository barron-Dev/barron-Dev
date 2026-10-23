from __future__ import annotations

import ipaddress
import logging
import os
import re
import secrets
import threading
import time
from urllib.parse import quote, urlsplit, urlunsplit

logger = logging.getLogger(__name__)
_ONION_HOST = re.compile(r"^[a-z2-7]{56}\.onion$", re.IGNORECASE)
def _bootstrap_complete(value: str) -> bool:
    """Parse Tor's bootstrap status without treating partial progress as ready."""
    return bool(re.search(r"(?:^|\s)PROGRESS=100(?:\s|$)", str(value or "")))


def _private_control_host(host: str) -> bool:
    value = host.strip().lower().rstrip(".")
    if value in {"localhost", "tor"} or value.endswith((".internal", ".local", ".railway.internal")):
        return True
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(not address.is_unspecified and not address.is_multicast and (address.is_loopback or address.is_private or address.is_link_local))


class TorControlProofCollector:
    """Collect per-request Tor control events without retaining descriptor bodies.

    Requires an authenticated local/private Tor ControlPort. SOCKS reachability,
    bootstrap status, or a descriptor event alone never proves a checked page.
    """

    def __init__(self, request_id: str, *, host: str, port: int, password: str | None = None,
                 cookie_path: str | None = None) -> None:
        self.request_id = str(request_id)
        self.host = host
        self.port = int(port)
        if not 1 <= self.port <= 65535:
            raise ValueError("tor_control_port_invalid")
        self.password = password
        self.cookie_path = cookie_path
        self.controller = None
        self.bootstrapped = False
        self.socks_auth_isolation_configured = False
        self.tor_version: str | None = None
        self._lock = threading.RLock()
        self._starts: dict[str, float] = {}
        # Only events inside the exact HTTP response window may attest a seed.
        # The digest is registered after bounded body read and must match proof_for.
        self._response_windows: dict[str, tuple[float, float, str]] = {}
        self._hsfetch_accepted: set[str] = set()
        self._descriptor_events: dict[str, list[tuple[float, str, bool]]] = {}
        self._streams: list[tuple[float, str, str, str, str]] = []
        self._socks_username = "ct_" + secrets.token_urlsafe(18)
        self._socks_password = secrets.token_urlsafe(32)
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
        password = os.getenv("CYCLOTHONE_DW_TOR_CONTROL_PASSWORD") or None
        cookie_path = os.getenv("CYCLOTHONE_DW_TOR_CONTROL_COOKIE") or None
        if not password and not cookie_path:
            raise RuntimeError("tor_control_auth_material_required")
        return cls(
            request_id,
            host=host,
            port=int(os.getenv("CYCLOTHONE_DW_TOR_CONTROL_PORT", "9051")),
            password=password,
            cookie_path=cookie_path,
        )

    def proxy_for_request(self, proxy_url: str) -> str:
        """Add request-scoped SOCKS credentials for Tor IsolateSOCKSAuth."""
        parsed = urlsplit(str(proxy_url or ""))
        if parsed.scheme not in {"socks5", "socks5h"} or not parsed.hostname:
            raise RuntimeError("tor_control_socks_proxy_invalid")
        if not _private_control_host(parsed.hostname):
            raise RuntimeError("tor_control_socks_proxy_must_be_private")
        if parsed.username or parsed.password:
            raise RuntimeError("tor_control_socks_proxy_must_not_contain_static_credentials")
        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        netloc = (
            f"{quote(self._socks_username, safe='')}:"
            f"{quote(self._socks_password, safe='')}@{host}"
        )
        if parsed.port:
            netloc += f":{parsed.port}"
        return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))

    def start(self) -> None:
        if not self.request_id.strip():
            raise RuntimeError("tor_control_request_id_required")
        if self.controller is not None:
            return
        try:
            from stem.control import Controller, EventType
        except ImportError as exc:
            raise RuntimeError("tor_control_stem_dependency_missing") from exc
        controller = Controller.from_port(address=self.host, port=self.port)
        try:
            if self.cookie_path:
                controller.authenticate(cookie_path=self.cookie_path)
            elif self.password:
                controller.authenticate(password=self.password)
            else:
                controller.authenticate()
            self.tor_version = str(controller.get_version())
            bootstrap = str(controller.get_info("status/bootstrap-phase", ""))
            self.bootstrapped = _bootstrap_complete(bootstrap)
            # Do not infer isolation from unique credentials alone: the configured
            # SocksPort must explicitly enable IsolateSOCKSAuth.
            socks_ports = controller.get_conf("SocksPort", multiple=True) or []
            if isinstance(socks_ports, str):
                socks_ports = [socks_ports]
            self.socks_auth_isolation_configured = any(
                "isolatesocksauth" in str(entry).lower()
                for entry in socks_ports
            )
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
        raw = str(
            getattr(event, "address", "")
            or getattr(event, "hs_address", "")
            or ""
        ).strip().lower().rstrip(".")
        # Tor's HS_DESC events carry the 56-character address without ".onion";
        # STREAM events normally carry the full hostname.
        if re.fullmatch(r"[a-z2-7]{56}", raw):
            return raw + ".onion"
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
                str(getattr(event, "socks_username", "") or ""),
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
            if reply.is_ok():
                with self._lock:
                    self._hsfetch_accepted.add(host)
            else:
                logger.info("Tor HSFETCH was rejected for a configured seed")
        except Exception as exc:
            logger.info("Tor HSFETCH command failed error=%s", type(exc).__name__)

    def complete_seed_response(self, seed_url: str, content_sha256: str) -> None:
        """Bind a response digest to the observed request window for one seed."""
        parsed = urlsplit(seed_url)
        host = (parsed.hostname or "").lower()
        started = self._starts.get(host)
        digest = str(content_sha256 or "").lower()
        if not _ONION_HOST.fullmatch(host) or started is None:
            raise RuntimeError("tor_control_seed_window_missing")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("tor_control_response_digest_invalid")
        ended = time.monotonic()
        if ended < started:
            raise RuntimeError("tor_control_seed_window_invalid")
        with self._lock:
            self._response_windows[host] = (started, ended, digest)

    def wait_for_proof(
        self,
        seed_url: str,
        content_sha256: str,
        *,
        timeout_seconds: float = 3.0,
        poll_interval_seconds: float = 0.1,
    ) -> dict[str, object]:
        """Wait briefly for asynchronous Tor events tied to this response."""
        deadline = time.monotonic() + max(0.0, min(float(timeout_seconds), 5.0))
        proof = self.proof_for(seed_url, content_sha256)
        required = (
            "route_verified", "hs_desc_content_received", "descriptor_fetched",
            "rendezvous_hop_verified", "stream_circuit_bound",
        )
        while not all(proof.get(field) is True for field in required):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(max(0.01, poll_interval_seconds), remaining))
            proof = self.proof_for(seed_url, content_sha256)
        return proof

    def proof_for(self, seed_url: str, content_sha256: str) -> dict[str, object]:
        parsed = urlsplit(seed_url)
        host = (parsed.hostname or "").lower()
        with self._lock:
            response_window = self._response_windows.get(host)
            if response_window is None:
                started, ended, bound_digest = float("inf"), float("-inf"), ""
            else:
                started, ended, bound_digest = response_window
            digest_matches_window = (
                bool(response_window)
                and re.fullmatch(r"[0-9a-f]{64}", str(content_sha256 or "").lower()) is not None
                and str(content_sha256).lower() == bound_digest
            )
            descriptor_events = [
                item for item in self._descriptor_events.get(host, [])
                if started <= item[0] <= ended
            ]
            streams = [
                item for item in self._streams
                if started <= item[0] <= ended
                and item[1] == host
                and item[2] == "SUCCEEDED"
                and item[3] not in {"", "0"}
                and item[4] == self._socks_username
            ]
            circuits = [
                item for item in self._circuits
                if started <= item[0] <= ended
                and item[2] == "BUILT"
                and item[3] in {"HS_CLIENT_REND", "HS_CLIENT_REND_JOINED"}
            ]
        with self._lock:
            hsfetch_accepted = host in self._hsfetch_accepted
        descriptor_fetched = hsfetch_accepted and any(
            action == "RECEIVED" and has_id for _, action, has_id in descriptor_events
        )
        content_received = hsfetch_accepted and any(
            action == "CONTENT" and has_content for _, action, has_content in descriptor_events
        )
        built_circuit_ids = {circ_id for _, circ_id, _, _ in circuits}
        bound_stream = next((stream for stream in streams if stream[3] in built_circuit_ids), None)
        rendezvous_verified = bound_stream is not None
        route_verified = bool(
            digest_matches_window
            and self.controller is not None and self.bootstrapped and hsfetch_accepted
            and self.socks_auth_isolation_configured
            and descriptor_fetched and content_received and rendezvous_verified
        )
        return {
            "service_request_id": self.request_id,
            "content_sha256": str(content_sha256).lower() if digest_matches_window else None,
            "response_window_bound": digest_matches_window,
            "tor_control_authenticated": self.controller is not None,
            "tor_bootstrap_complete": self.bootstrapped,
            "tor_socks_auth_isolation_configured": self.socks_auth_isolation_configured,
            "tor_version": self.tor_version,
            "hsfetch_accepted": hsfetch_accepted,
            "route_verified": route_verified,
            "hs_desc_content_received": content_received,
            "descriptor_fetched": descriptor_fetched,
            "rendezvous_hop_verified": rendezvous_verified,
            "stream_circuit_bound": bound_stream is not None,
            "socks_auth_bound": bound_stream is not None,
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
