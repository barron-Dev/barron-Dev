"""Bounded RTSP ingestion using the installed FFmpeg executable.

This adapter accepts only server-configured, credential-free RTSP URLs whose
hostname is explicitly allowlisted. Camera credentials must not be embedded in
URLs or passed on command lines. Deployments needing authenticated RTSP must
supply a reviewed local credential-broker/proxy integration before use.
Network egress policy must independently enforce the same camera allowlist.
"""
from __future__ import annotations

import asyncio
import hashlib
import math
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit


class CameraConfigurationError(ValueError):
    """The camera endpoint or runtime configuration is not safe to use."""


class CameraStreamError(RuntimeError):
    """The real stream failed, timed out, or produced invalid media."""


@dataclass(frozen=True, slots=True)
class RTSPCameraConfig:
    tenant_id: str
    camera_id: str
    endpoint: str
    allowed_hosts: frozenset[str]
    frames_per_second: int = 5
    max_frame_bytes: int = 8 * 1024 * 1024
    read_timeout_seconds: float = 15.0

    def __post_init__(self) -> None:
        if not isinstance(self.tenant_id, str) or not self.tenant_id.strip():
            raise CameraConfigurationError("tenant_id_required")
        if not isinstance(self.camera_id, str) or not self.camera_id.strip():
            raise CameraConfigurationError("camera_id_required")
        if not isinstance(self.endpoint, str):
            raise CameraConfigurationError("endpoint_must_be_string")
        parsed = urlsplit(self.endpoint)
        if parsed.scheme not in {"rtsp", "rtsps"}:
            raise CameraConfigurationError("endpoint_must_use_rtsp_or_rtsps")
        if not parsed.hostname or parsed.username is not None or parsed.password is not None:
            raise CameraConfigurationError("endpoint_host_required_and_embedded_credentials_forbidden")
        if parsed.fragment or parsed.query:
            raise CameraConfigurationError("query_and_fragment_components_forbidden")
        try:
            parsed.port
        except ValueError as exc:
            raise CameraConfigurationError("invalid_endpoint_port") from exc
        host = parsed.hostname.rstrip(".").lower()
        allowed = {item.rstrip(".").lower() for item in self.allowed_hosts}
        if not allowed or host not in allowed:
            raise CameraConfigurationError("endpoint_host_not_explicitly_allowlisted")
        if isinstance(self.frames_per_second, bool) or not isinstance(self.frames_per_second, int) or not 1 <= self.frames_per_second <= 10:
            raise CameraConfigurationError("frames_per_second_must_be_between_1_and_10")
        if isinstance(self.max_frame_bytes, bool) or not isinstance(self.max_frame_bytes, int) or not 1024 <= self.max_frame_bytes <= 32 * 1024 * 1024:
            raise CameraConfigurationError("max_frame_bytes_out_of_range")
        if (isinstance(self.read_timeout_seconds, bool)
                or not isinstance(self.read_timeout_seconds, (int, float))
                or not math.isfinite(self.read_timeout_seconds)
                or not 1 <= self.read_timeout_seconds <= 120):
            raise CameraConfigurationError("read_timeout_seconds_out_of_range")


@dataclass(frozen=True, slots=True)
class VideoFrame:
    tenant_id: str
    camera_id: str
    sequence: int
    observed_at: datetime
    sha256: str
    jpeg_bytes: bytes


def _extract_jpegs(buffer: bytearray, max_frame_bytes: int):
    """Yield complete JPEGs from an image2pipe byte stream, bounded in memory."""
    while True:
        start = buffer.find(b"\xff\xd8")
        if start < 0:
            if len(buffer) > 1:
                del buffer[:-1]
            return
        if start:
            del buffer[:start]
        end = buffer.find(b"\xff\xd9", 2)
        if end < 0:
            if len(buffer) > max_frame_bytes:
                raise CameraStreamError("frame_exceeded_maximum_size")
            return
        end += 2
        if end > max_frame_bytes:
            raise CameraStreamError("frame_exceeded_maximum_size")
        frame = bytes(buffer[:end])
        del buffer[:end]
        yield frame


async def stream_rtsp_frames(config: RTSPCameraConfig):
    """Yield actual JPEG frames from FFmpeg; queue policy drops stale frames.

    No detection result is produced here. A separately configured detector
    must consume these real frames and return provenance-bearing observations.
    The subprocess is terminated when the consumer stops or the stream fails.
    """
    executable = shutil.which("ffmpeg")
    if executable is None:
        raise CameraStreamError("ffmpeg_executable_not_installed")

    command = [
        executable, "-hide_banner", "-loglevel", "error", "-nostdin",
        "-rtsp_transport", "tcp", "-i", config.endpoint,
        "-an", "-vf", f"fps={config.frames_per_second}",
        "-f", "image2pipe", "-vcodec", "mjpeg", "pipe:1",
    ]
    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    queue: asyncio.Queue[VideoFrame | None] = asyncio.Queue(maxsize=1)
    failure: BaseException | None = None

    async def produce() -> None:
        nonlocal failure
        buffer = bytearray()
        sequence = 0
        try:
            assert process.stdout is not None
            while True:
                chunk = await process.stdout.read(64 * 1024)
                if not chunk:
                    break
                buffer.extend(chunk)
                if len(buffer) > config.max_frame_bytes * 2 and b"\xff\xd8" not in buffer:
                    raise CameraStreamError("stream_output_buffer_limit_exceeded")
                for jpeg in _extract_jpegs(buffer, config.max_frame_bytes):
                    sequence += 1
                    frame = VideoFrame(
                        tenant_id=config.tenant_id,
                        camera_id=config.camera_id,
                        sequence=sequence,
                        observed_at=datetime.now(timezone.utc),
                        sha256=hashlib.sha256(jpeg).hexdigest(),
                        jpeg_bytes=jpeg,
                    )
                    if queue.full():
                        try:
                            queue.get_nowait()
                            queue.task_done()
                        except asyncio.QueueEmpty:
                            pass
                    queue.put_nowait(frame)
            return_code = await process.wait()
            if return_code != 0:
                raise CameraStreamError(f"ffmpeg_stream_failed_exit_{return_code}")
            if not sequence:
                raise CameraStreamError("stream_ended_without_video_frames")
        except asyncio.CancelledError:
            raise
        except BaseException as exc:
            failure = exc
        finally:
            if queue.full():
                try:
                    queue.get_nowait()
                    queue.task_done()
                except asyncio.QueueEmpty:
                    pass
            queue.put_nowait(None)

    producer = asyncio.create_task(produce(), name=f"watchtower-rtsp-{config.camera_id}")
    try:
        while True:
            try:
                item = await asyncio.wait_for(queue.get(), timeout=config.read_timeout_seconds)
            except asyncio.TimeoutError as exc:
                raise CameraStreamError("camera_stream_read_timeout") from exc
            if item is None:
                break
            queue.task_done()
            yield item
        await producer
        if failure is not None:
            raise CameraStreamError("rtsp_producer_failed") from failure
    finally:
        if not producer.done():
            producer.cancel()
        if process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=3)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
        await asyncio.gather(producer, return_exceptions=True)
