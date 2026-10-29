import pytest
from fastapi import HTTPException

from cyclothone.api.routes.watchtower import _validated_endpoint


def test_watchtower_endpoint_requires_server_allowlisted_host(monkeypatch):
    monkeypatch.setenv("WATCHTOWER_CAMERA_ALLOWED_HOSTS", "10.20.30.40, camera.internal ")
    assert _validated_endpoint("rtsps://camera.internal/live") == ("camera.internal", "rtsps")
    with pytest.raises(HTTPException) as exc:
        _validated_endpoint("rtsp://10.20.30.41/live")
    assert exc.value.detail == "camera_host_not_allowlisted_by_server"


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://camera.internal/live",
        "rtsp://user:password@camera.internal/live",
        "rtsp://camera.internal/live?token=secret",
        "rtsp://camera.internal/live#fragment",
    ],
)
def test_watchtower_endpoint_rejects_unsafe_urls(monkeypatch, endpoint):
    monkeypatch.setenv("WATCHTOWER_CAMERA_ALLOWED_HOSTS", "camera.internal")
    with pytest.raises(HTTPException):
        _validated_endpoint(endpoint)
