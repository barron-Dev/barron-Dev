import asyncio

import pytest

from cyclothone.watchtower.onvif import ONVIFProtocolError, _read_bounded_body


class _ChunkedResponse:
    def __init__(self, chunks):
        self._chunks = chunks

    async def aiter_bytes(self):
        for chunk in self._chunks:
            yield chunk


def test_onvif_response_body_reader_accepts_bounded_stream():
    body = asyncio.run(_read_bounded_body(_ChunkedResponse([b"<soap>", b"</soap>"]), max_bytes=32))
    assert body == b"<soap></soap>"


def test_onvif_response_body_reader_rejects_oversized_stream_without_full_buffering():
    async def chunks():
        yield b"a" * 8
        yield b"b" * 8
        yield b"c" * 8

    response = type("Response", (), {"aiter_bytes": lambda self: chunks()})()
    with pytest.raises(ONVIFProtocolError, match="response_too_large"):
        asyncio.run(_read_bounded_body(response, max_bytes=16))
