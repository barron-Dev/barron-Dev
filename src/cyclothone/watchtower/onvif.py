"""Bounded ONVIF Media1 client for explicitly configured, authorized cameras.

This module negotiates profiles and obtains RTSP stream URIs from a camera's
ONVIF Device/Media services. It does not perform subnet scanning or persist
credentials. Credentials are passed separately and held only for the request
lifetime. Network egress policy must independently restrict reachable devices.
"""
from __future__ import annotations

import math
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx


SOAP_NS = "http://www.w3.org/2003/05/soap-envelope"
DEVICE_NS = "http://www.onvif.org/ver10/device/wsdl"
MEDIA_NS = "http://www.onvif.org/ver10/media/wsdl"
SCHEMA_NS = "http://www.onvif.org/ver10/schema"
NS = {"s": SOAP_NS, "d": DEVICE_NS, "m": MEDIA_NS, "tt": SCHEMA_NS}


class ONVIFConfigurationError(ValueError):
    """An ONVIF endpoint or credential configuration is invalid."""


class ONVIFProtocolError(RuntimeError):
    """The real camera returned an invalid or unsuccessful ONVIF response."""


@dataclass(frozen=True, slots=True)
class ONVIFProfile:
    token: str
    name: str
    stream_uri: str


def _validate_http_endpoint(endpoint: str, allowed_hosts: frozenset[str]) -> str:
    if not isinstance(endpoint, str):
        raise ONVIFConfigurationError("endpoint_must_be_string")
    parsed = urlsplit(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ONVIFConfigurationError("endpoint_must_use_http_or_https")
    if parsed.username is not None or parsed.password is not None:
        raise ONVIFConfigurationError("embedded_credentials_forbidden")
    if parsed.query or parsed.fragment:
        raise ONVIFConfigurationError("query_and_fragment_components_forbidden")
    try:
        parsed.port
    except ValueError as exc:
        raise ONVIFConfigurationError("invalid_endpoint_port") from exc
    host = parsed.hostname.rstrip(".").lower()
    allowed = {item.rstrip(".").lower() for item in allowed_hosts}
    if not allowed or host not in allowed:
        raise ONVIFConfigurationError("endpoint_host_not_explicitly_allowlisted")
    return host


def _soap_envelope(operation: str, namespace: str, fields: dict[str, str] | None = None) -> bytes:
    envelope = ET.Element(f"{{{SOAP_NS}}}Envelope")
    body = ET.SubElement(envelope, f"{{{SOAP_NS}}}Body")
    request = ET.SubElement(body, f"{{{namespace}}}{operation}")
    for key, value in (fields or {}).items():
        tag = key if key.startswith("{") else f"{{{namespace}}}{key}"
        ET.SubElement(request, tag).text = value
    return ET.tostring(envelope, encoding="utf-8", xml_declaration=True)


def _body_root(payload: bytes) -> ET.Element:
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise ONVIFProtocolError("invalid_onvif_xml") from exc
    fault = root.find(".//s:Fault", NS)
    if fault is not None:
        code = fault.findtext(".//s:Value", default="onvif_fault", namespaces=NS)
        raise ONVIFProtocolError(f"onvif_soap_fault:{code[:80]}")
    body = root.find("s:Body", NS)
    if body is None or len(body) != 1:
        raise ONVIFProtocolError("onvif_body_missing_or_ambiguous")
    return body[0]


class ONVIFMediaClient:
    """ONVIF Media1 profile negotiation for a configured camera endpoint."""

    def __init__(
        self,
        *,
        device_service_url: str,
        allowed_hosts: frozenset[str],
        username: str,
        password: str,
        timeout_seconds: float = 5.0,
    ) -> None:
        host = _validate_http_endpoint(device_service_url, allowed_hosts)
        if not isinstance(username, str) or not username or not isinstance(password, str) or not password:
            raise ONVIFConfigurationError("separate_camera_credentials_required")
        if (isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not math.isfinite(timeout_seconds) or not 0.5 <= timeout_seconds <= 15):
            raise ONVIFConfigurationError("timeout_seconds_out_of_range")
        self._device_url = device_service_url
        self._allowed_hosts = allowed_hosts
        self._host = host
        self._auth = httpx.DigestAuth(username, password)
        self._timeout = timeout_seconds

    async def _post(self, endpoint: str, action: str, payload: bytes) -> ET.Element:
        host = _validate_http_endpoint(endpoint, self._allowed_hosts)
        if host != self._host:
            raise ONVIFConfigurationError("cross_host_service_endpoint_forbidden")
        headers = {
            "Content-Type": "application/soap+xml; charset=utf-8",
            "SOAPAction": action,
        }
        try:
            async with httpx.AsyncClient(
                auth=self._auth, timeout=self._timeout, follow_redirects=False,
                verify=True, trust_env=False,
            ) as client:
                async with client.stream("POST", endpoint, content=payload, headers=headers) as response:
                    if response.is_redirect:
                        raise ONVIFProtocolError("onvif_redirect_forbidden")
                    if response.status_code < 200 or response.status_code >= 300:
                        raise ONVIFProtocolError(f"onvif_http_status_{response.status_code}")
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > 2 * 1024 * 1024:
                            raise ONVIFProtocolError("onvif_response_too_large")
        except httpx.HTTPError as exc:
            raise ONVIFProtocolError("onvif_transport_failed") from exc
        return _body_root(bytes(body))

    async def negotiate_profiles(self) -> tuple[ONVIFProfile, ...]:
        """Return actual camera profiles and their authorized RTSP stream URIs."""
        capabilities = await self._post(
            self._device_url,
            DEVICE_NS + "/GetCapabilities",
            _soap_envelope("GetCapabilities", DEVICE_NS, {"Category": "Media"}),
        )
        media_xaddr = capabilities.find(".//tt:Media/tt:XAddr", NS)
        if media_xaddr is None or not media_xaddr.text:
            # Some firmware emits the Media element in the Device namespace.
            media_xaddr = capabilities.find(".//d:Media/d:XAddr", NS)
        if media_xaddr is None or not media_xaddr.text:
            raise ONVIFProtocolError("media_service_endpoint_missing")
        media_url = media_xaddr.text.strip()
        _validate_http_endpoint(media_url, self._allowed_hosts)
        profiles_response = await self._post(
            media_url,
            MEDIA_NS + "/GetProfiles",
            _soap_envelope("GetProfiles", MEDIA_NS),
        )
        profile_nodes = profiles_response.findall(".//tt:Profiles", NS)
        if not profile_nodes:
            profile_nodes = profiles_response.findall(".//m:Profiles", NS)
        if not profile_nodes:
            raise ONVIFProtocolError("camera_returned_no_media_profiles")

        profiles: list[ONVIFProfile] = []
        for node in profile_nodes:
            token = node.attrib.get("token", "").strip()
            name = node.findtext("tt:Name", default="", namespaces=NS).strip()
            if not token:
                raise ONVIFProtocolError("camera_profile_token_missing")
            # Construct the nested ONVIF StreamSetup/Transport structure explicitly.
            request = ET.Element(f"{{{SOAP_NS}}}Envelope")
            body = ET.SubElement(request, f"{{{SOAP_NS}}}Body")
            operation = ET.SubElement(body, f"{{{MEDIA_NS}}}GetStreamUri")
            setup = ET.SubElement(operation, f"{{{MEDIA_NS}}}StreamSetup")
            ET.SubElement(setup, f"{{{SCHEMA_NS}}}Stream").text = "RTP-Unicast"
            transport = ET.SubElement(setup, f"{{{SCHEMA_NS}}}Transport")
            ET.SubElement(transport, f"{{{SCHEMA_NS}}}Protocol").text = "RTSP"
            ET.SubElement(operation, f"{{{MEDIA_NS}}}ProfileToken").text = token
            stream_response = await self._post(
                media_url, MEDIA_NS + "/GetStreamUri",
                ET.tostring(request, encoding="utf-8", xml_declaration=True),
            )
            uri = stream_response.findtext(".//tt:Uri", default="", namespaces=NS).strip()
            if not uri:
                raise ONVIFProtocolError("camera_stream_uri_missing")
            parsed = urlsplit(uri)
            if parsed.scheme not in {"rtsp", "rtsps"} or not parsed.hostname:
                raise ONVIFProtocolError("camera_returned_non_rtsp_stream_uri")
            if parsed.username is not None or parsed.password is not None:
                raise ONVIFProtocolError("camera_stream_uri_embeds_credentials")
            if parsed.query or parsed.fragment:
                raise ONVIFProtocolError("camera_stream_uri_query_or_fragment_forbidden")
            if parsed.hostname.rstrip(".").lower() not in {
                item.rstrip(".").lower() for item in self._allowed_hosts
            }:
                raise ONVIFProtocolError("camera_stream_host_not_allowlisted")
            profiles.append(ONVIFProfile(token=token, name=name or token, stream_uri=uri))
        return tuple(profiles)
