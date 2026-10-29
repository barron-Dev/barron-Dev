import pytest

from cyclothone.watchtower.onvif import (
    DEVICE_NS,
    MEDIA_NS,
    NS,
    SOAP_NS,
    ONVIFConfigurationError,
    ONVIFProtocolError,
    ONVIFMediaClient,
    _body_root,
    _soap_envelope,
    _validate_http_endpoint,
)


def test_onvif_endpoint_requires_explicit_allowlist_and_separate_credentials():
    with pytest.raises(ONVIFConfigurationError, match="not_explicitly_allowlisted"):
        _validate_http_endpoint("http://10.0.0.20/onvif/device_service", frozenset({"10.0.0.21"}))
    with pytest.raises(ONVIFConfigurationError, match="embedded_credentials_forbidden"):
        _validate_http_endpoint("http://operator:secret@10.0.0.20/onvif", frozenset({"10.0.0.20"}))
    with pytest.raises(ONVIFConfigurationError, match="query_and_fragment"):
        _validate_http_endpoint("http://10.0.0.20/onvif?token=secret", frozenset({"10.0.0.20"}))


def test_onvif_client_requires_credentials_outside_endpoint_and_bounded_timeout():
    with pytest.raises(ONVIFConfigurationError, match="separate_camera_credentials_required"):
        ONVIFMediaClient(
            device_service_url="http://10.0.0.20/onvif/device_service",
            allowed_hosts=frozenset({"10.0.0.20"}),
            username="",
            password="secret",
        )
    with pytest.raises(ONVIFConfigurationError, match="timeout_seconds_out_of_range"):
        ONVIFMediaClient(
            device_service_url="http://10.0.0.20/onvif/device_service",
            allowed_hosts=frozenset({"10.0.0.20"}),
            username="operator",
            password="secret",
            timeout_seconds=float("nan"),
        )


def test_onvif_soap_envelope_has_expected_operation_namespace():
    payload = _soap_envelope("GetProfiles", MEDIA_NS)
    root = _body_root(payload)
    assert root.tag == f"{{{MEDIA_NS}}}GetProfiles"


def test_onvif_soap_fault_is_not_treated_as_success():
    payload = f"""<s:Envelope xmlns:s="{SOAP_NS}">
      <s:Body><s:Fault><s:Code><s:Value>s:Sender</s:Value></s:Code></s:Fault></s:Body>
    </s:Envelope>""".encode()
    with pytest.raises(ONVIFProtocolError, match="onvif_soap_fault"):
        _body_root(payload)


def test_onvif_soap_response_rejects_ambiguous_body():
    payload = f"""<s:Envelope xmlns:s="{SOAP_NS}" xmlns:d="{DEVICE_NS}" xmlns:m="{MEDIA_NS}">
      <s:Body><d:GetCapabilitiesResponse/><m:GetProfilesResponse/></s:Body>
    </s:Envelope>""".encode()
    with pytest.raises(ONVIFProtocolError, match="ambiguous"):
        _body_root(payload)
