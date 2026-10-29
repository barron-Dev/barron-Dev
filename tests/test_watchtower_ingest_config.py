import math

import pytest

from cyclothone.watchtower.ingest import CameraConfigurationError, RTSPCameraConfig


def test_rtsp_config_requires_explicit_host_allowlist():
    with pytest.raises(CameraConfigurationError, match="not_explicitly_allowlisted"):
        RTSPCameraConfig(
            tenant_id="tenant", camera_id="camera",
            endpoint="rtsp://10.20.30.40/live",
            allowed_hosts=frozenset({"10.20.30.41"}),
        )


def test_rtsp_config_rejects_embedded_credentials():
    with pytest.raises(CameraConfigurationError, match="embedded_credentials_forbidden"):
        RTSPCameraConfig(
            tenant_id="tenant", camera_id="camera",
            endpoint="rtsp://operator:secret@10.20.30.40/live",
            allowed_hosts=frozenset({"10.20.30.40"}),
        )


def test_rtsp_config_rejects_query_tokens_and_non_rtsp_protocols():
    with pytest.raises(CameraConfigurationError, match="query_and_fragment"):
        RTSPCameraConfig(
            tenant_id="tenant", camera_id="camera",
            endpoint="rtsp://10.20.30.40/live?token=secret",
            allowed_hosts=frozenset({"10.20.30.40"}),
        )
    with pytest.raises(CameraConfigurationError, match="rtsp_or_rtsps"):
        RTSPCameraConfig(
            tenant_id="tenant", camera_id="camera",
            endpoint="http://10.20.30.40/live",
            allowed_hosts=frozenset({"10.20.30.40"}),
        )


def test_rtsp_config_rejects_unsafe_frame_rates_and_timeouts():
    with pytest.raises(CameraConfigurationError, match="between_1_and_10"):
        RTSPCameraConfig(
            tenant_id="tenant", camera_id="camera",
            endpoint="rtsp://10.20.30.40/live",
            allowed_hosts=frozenset({"10.20.30.40"}),
            frames_per_second=60,
        )
    with pytest.raises(CameraConfigurationError, match="timeout_out_of_range"):
        RTSPCameraConfig(
            tenant_id="tenant", camera_id="camera",
            endpoint="rtsp://10.20.30.40/live",
            allowed_hosts=frozenset({"10.20.30.40"}),
            read_timeout_seconds=math.nan,
        )
