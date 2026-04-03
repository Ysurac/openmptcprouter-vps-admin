"""
Unit tests for the /speedtest download and upload endpoints.

The endpoints are extracted into a minimal FastAPI app so tests run
without the module-level I/O (shorewall files, config, etc.) that the
full omr-admin.py performs at import time.
"""

import io
import time
import pytest
from typing import Optional
from unittest.mock import patch

from fastapi import Depends, FastAPI, Query, UploadFile
from fastapi.testclient import TestClient
from starlette.responses import StreamingResponse


# ---------------------------------------------------------------------------
# Minimal test app – mirrors the real speedtest logic exactly
# ---------------------------------------------------------------------------

test_app = FastAPI()


class _FakeUser:
    username = "testuser"
    permissions = "rw"


def _fake_user():
    return _FakeUser()


@test_app.get("/speedtest")
async def speedtest(
    size: Optional[int] = Query(10),
    current_user=Depends(_fake_user),
):
    size_bytes = min(max(size, 1), 100) * 1024 * 1024
    chunk = b"\x00" * 65536

    async def generate():
        remaining = size_bytes
        while remaining > 0:
            send = min(65536, remaining)
            yield chunk[:send]
            remaining -= send

    return StreamingResponse(
        generate(),
        media_type="application/octet-stream",
        headers={
            "Content-Length": str(size_bytes),
            "Cache-Control": "no-store",
            "Content-Disposition": "attachment; filename=speedtest.bin",
        },
    )


@test_app.post("/speedtest")
async def speedtestul(
    file: UploadFile,
    current_user=Depends(_fake_user),
):
    if not file:
        return {"result": "No upload file sent"}
    start = time.time()
    size = 0
    while True:
        chunk = await file.read(65536)
        if not chunk:
            break
        size += len(chunk)
    elapsed = time.time() - start
    speed_mbps = (
        round((size * 8) / (elapsed * 1_000_000), 2)
        if elapsed > 0 and size > 0
        else 0
    )
    return {"bytes": size, "duration": round(elapsed, 3), "speed_mbps": speed_mbps}


client = TestClient(test_app)

MB = 1024 * 1024


# ---------------------------------------------------------------------------
# Download tests
# ---------------------------------------------------------------------------


class TestSpeedtestDownload:
    def test_default_size_is_10mb(self):
        r = client.get("/speedtest")
        assert r.status_code == 200
        assert len(r.content) == 10 * MB

    def test_custom_size(self):
        r = client.get("/speedtest?size=2")
        assert r.status_code == 200
        assert len(r.content) == 2 * MB

    def test_size_capped_at_100mb(self):
        r = client.get("/speedtest?size=200")
        assert r.status_code == 200
        assert len(r.content) == 100 * MB

    def test_size_minimum_is_1mb(self):
        r = client.get("/speedtest?size=0")
        assert r.status_code == 200
        assert len(r.content) == 1 * MB

    def test_size_negative_clamped_to_1mb(self):
        r = client.get("/speedtest?size=-5")
        assert r.status_code == 200
        assert len(r.content) == 1 * MB

    def test_content_length_header_matches_body(self):
        r = client.get("/speedtest?size=1")
        assert r.status_code == 200
        assert int(r.headers["content-length"]) == len(r.content)

    def test_cache_control_no_store(self):
        r = client.get("/speedtest?size=1")
        assert r.headers["cache-control"] == "no-store"

    def test_content_disposition_header(self):
        r = client.get("/speedtest?size=1")
        assert r.headers["content-disposition"] == "attachment; filename=speedtest.bin"

    def test_content_type_is_octet_stream(self):
        r = client.get("/speedtest?size=1")
        assert "application/octet-stream" in r.headers["content-type"]

    def test_body_is_all_zeros(self):
        r = client.get("/speedtest?size=1")
        assert r.content == b"\x00" * MB


# ---------------------------------------------------------------------------
# Upload tests
# ---------------------------------------------------------------------------


class TestSpeedtestUpload:
    def _upload(self, data: bytes) -> dict:
        return client.post(
            "/speedtest",
            files={"file": ("upload.bin", io.BytesIO(data), "application/octet-stream")},
        ).json()

    def test_returns_correct_byte_count(self):
        payload = b"x" * (512 * 1024)  # 512 KB
        result = self._upload(payload)
        assert result["bytes"] == len(payload)

    def test_returns_duration(self):
        result = self._upload(b"x" * 1024)
        assert "duration" in result
        assert isinstance(result["duration"], float)
        assert result["duration"] >= 0

    def test_returns_speed_mbps(self):
        result = self._upload(b"x" * (256 * 1024))
        assert "speed_mbps" in result
        assert isinstance(result["speed_mbps"], float)
        assert result["speed_mbps"] >= 0

    def test_speed_unit_is_megabits(self):
        """speed_mbps = bytes * 8 / (elapsed * 1e6) — verify the formula."""
        import time as _time_module
        _real_time = _time_module.time  # capture before patching
        payload = b"x" * MB  # 1 MB = 8 Mbit
        fake_elapsed = 1.0  # pretend it took exactly 1 second → 8 Mbps

        _calls = iter([0.0, fake_elapsed])
        with patch("time.time", side_effect=lambda: next(_calls, _real_time())):
            result = self._upload(payload)

        assert result["bytes"] == MB
        expected = round((MB * 8) / (fake_elapsed * 1_000_000), 2)
        assert result["speed_mbps"] == expected

    def test_zero_elapsed_does_not_crash(self):
        """If time.time returns the same value twice, speed should be 0."""
        with patch("time.time", return_value=0.0):
            result = self._upload(b"x" * 1024)
        assert result["speed_mbps"] == 0

    def test_large_upload(self):
        payload = b"x" * (2 * MB)
        result = self._upload(payload)
        assert result["bytes"] == 2 * MB
        assert result["speed_mbps"] > 0

    def test_small_upload(self):
        payload = b"x" * 100
        result = self._upload(payload)
        assert result["bytes"] == 100

    def test_response_status_200(self):
        r = client.post(
            "/speedtest",
            files={"file": ("f.bin", io.BytesIO(b"hello"), "application/octet-stream")},
        )
        assert r.status_code == 200
