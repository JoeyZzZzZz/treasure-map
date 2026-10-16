# Copyright (C) 2026 JoeyZzZzZz
# SPDX-License-Identifier: Apache-2.0
"""``UrlFetcher`` + ``download_verified`` against a real HTTP server on the loopback interface.

urllib returns a short body without an error when a connection drops before Content-Length is
reached (or before the end of a body sent without one), raises IncompleteRead when a chunked body
loses its closing chunk, and raises HTTPError for a 416. Faking ``urlopen`` would test a guess of
those semantics; here the real client talks to a real ``http.server``, so a transfer that stopped
(kept, resumed next run) is told apart from a file the server sent whole but smaller than the lock
(a mismatch, deleted — resuming it could never succeed).
"""

from __future__ import annotations

import hashlib
import http.server
import socket
import threading
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from treasure_map.lib.setup.fetch import FetchError, UrlFetcher, download_verified
from treasure_map.lib.setup.toolchain_lock import Asset

# The real network entry points, taken before the autouse guard in tests/conftest.py replaces
# them for each test; the fixture below hands them back for the loopback address only.
_URLOPEN = urllib.request.urlopen
_CREATE_CONNECTION = socket.create_connection

PAYLOAD = bytes(range(256)) * 12  # what the lock pins: 3072 bytes
SMALL = PAYLOAD[:1000]  # a mirror's complete file, smaller than the lock
DROP_AT = 1200  # where a dropped connection stops


@dataclass
class _State:
    mode: str = "ok"  # ok | small | drop
    framing: str = "length"  # how a 200 body ends: length (Content-Length) | chunked | close
    honours_range: bool = True  # False: a Range request gets the whole file again (200)
    ranges: list[str | None] = field(default_factory=list)


def _handler(state: _State) -> type[http.server.BaseHTTPRequestHandler]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_a: object) -> None:
            return None

        # do_GET is the handler name http.server dispatches to, so it cannot be snake_case.
        def do_GET(self) -> None:  # noqa
            rng = self.headers.get("Range")
            state.ranges.append(rng)
            body = SMALL if state.mode == "small" else PAYLOAD
            if rng and state.honours_range:
                start = int(rng.removeprefix("bytes=").split("-")[0])
                if start >= len(body):
                    self.send_response(416)
                    self.send_header("Content-Range", f"bytes */{len(body)}")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self.send_response(206)
                self.send_header("Content-Range", f"bytes {start}-{len(body) - 1}/{len(body)}")
                self.send_header("Content-Length", str(len(body) - start))
                self.end_headers()
                self.wfile.write(body[start:])
                return
            sent = body[:DROP_AT] if state.mode == "drop" else body
            if state.framing == "chunked":
                # "drop": the connection closes before the closing zero-size chunk
                self.protocol_version = "HTTP/1.1"
                self.send_response(200)
                self.send_header("Transfer-Encoding", "chunked")
                self.send_header("Connection", "close")
                self.end_headers()
                for i in range(0, len(sent), 400):
                    piece = sent[i : i + 400]
                    self.wfile.write(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
                if state.mode != "drop":
                    self.wfile.write(b"0\r\n\r\n")
                return
            self.send_response(200)
            if state.framing == "length":
                self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            # "drop": the connection closes (HTTP/1.0) before the whole body is sent; without a
            # Content-Length ("close") that end looks the same as the real one
            self.wfile.write(sent)

    return Handler


@pytest.fixture
def server(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[_State, Asset]]:
    def _loopback_only(address: tuple[str, int], *a: object, **k: object) -> socket.socket:
        assert address[0] == "127.0.0.1", f"network in unit test: {address}"
        return _CREATE_CONNECTION(address, *a, **k)  # type: ignore[arg-type]

    monkeypatch.setattr(urllib.request, "urlopen", _URLOPEN)
    monkeypatch.setattr(socket, "create_connection", _loopback_only)
    for var in ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("no_proxy", "*")
    state = _State()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _handler(state))
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    asset = Asset(
        url=f"http://127.0.0.1:{srv.server_address[1]}/tool.zip",
        sha256=hashlib.sha256(PAYLOAD).hexdigest(),
        size=len(PAYLOAD),
        kind="zip",
    )
    try:
        yield state, asset
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=5)


def _download(asset: Asset, staging: Path) -> str:
    try:
        out = download_verified(asset, staging, UrlFetcher(timeout=10))
    except FetchError as exc:
        return str(exc)
    return "ok" if out.read_bytes() == PAYLOAD else "wrong bytes"


def test_a_complete_but_smaller_file_is_a_mismatch_not_a_resume(
    server: tuple[_State, Asset], tmp_path: Path
) -> None:
    """A 200 whose body reached its Content-Length is the server's whole file: shorter than the
    lock, it is deleted as a mismatch — on every run, never "run again to resume".

    MUTATION: UrlFetcher returns False after a whole response (completeness never reported)
    -> "download stopped at 1000 of 3072 bytes; run again to resume it", the .part kept -> RED."""
    state, asset = server
    state.mode = "small"
    staging = tmp_path / "dl"
    for _run in range(2):
        outcome = _download(asset, staging)
        assert "pinned 3072 bytes" in outcome and "deleted" in outcome, outcome
        assert "resume" not in outcome
        assert not (staging / "tool.zip.part").exists()
    assert state.ranges == [None, None]  # nothing left to resume from


def test_a_416_below_the_pinned_size_is_a_mismatch(
    server: tuple[_State, Asset], tmp_path: Path
) -> None:
    """A .part shorter than the lock, and the server has nothing past it (416): the server's file
    is smaller than the lock, so the .part is deleted as a mismatch instead of kept to resume.

    MUTATION: UrlFetcher returns False on a 416 -> the .part stays and every run asks to resume
    -> RED.
    MUTATION: download_verified ignores the completeness flag (any short file is a resume) ->
    RED here and in the test above."""
    state, asset = server
    state.mode = "small"
    staging = tmp_path / "dl"
    staging.mkdir()
    (staging / "tool.zip.part").write_bytes(SMALL)
    outcome = _download(asset, staging)
    assert state.ranges == [f"bytes={len(SMALL)}-"]
    assert "pinned 3072 bytes" in outcome and "deleted" in outcome, outcome
    assert not (staging / "tool.zip.part").exists()


def test_a_dropped_connection_is_kept_and_resumed(
    server: tuple[_State, Asset], tmp_path: Path
) -> None:
    """The other side of the same check: a 200 that stopped short of its Content-Length is a
    transfer that stopped, kept for the next run, which resumes it with a Range request.

    MUTATION: UrlFetcher reports every response as complete -> the dropped .part is deleted as a
    mismatch -> RED."""
    state, asset = server
    state.mode = "drop"
    staging = tmp_path / "dl"
    outcome = _download(asset, staging)
    assert "run again to resume" in outcome, outcome
    assert (staging / "tool.zip.part").stat().st_size == DROP_AT
    state.mode = "ok"
    assert _download(asset, staging) == "ok"
    assert state.ranges == [None, f"bytes={DROP_AT}-"]


def test_a_resume_that_reaches_the_servers_whole_size_short_of_the_lock_is_a_mismatch(
    server: tuple[_State, Asset], tmp_path: Path
) -> None:
    """A .part of 500 bytes resumed with a 206 whose Content-Range total is the server's whole
    file (1000 bytes, short of the lock): that total is where the resource ends, so the .part is
    a mismatch on this run — not kept for a run that would only meet a 416.

    MUTATION: read no total from the 206's Content-Range (end = None) -> "run again to resume
    it", the .part kept at 1000 bytes -> RED (observed)."""
    state, asset = server
    state.mode = "small"
    staging = tmp_path / "dl"
    staging.mkdir()
    (staging / "tool.zip.part").write_bytes(SMALL[:500])
    outcome = _download(asset, staging)
    assert state.ranges == ["bytes=500-"]
    assert "pinned 3072 bytes" in outcome and "deleted" in outcome, outcome
    assert not (staging / "tool.zip.part").exists()


def test_a_chunked_body_shorter_than_the_lock_is_a_mismatch_from_the_first_run(
    server: tuple[_State, Asset], tmp_path: Path
) -> None:
    """No Content-Length and no Range support: the body comes in chunks, and its closing chunk
    is where the server says the file ends (a body cut before it raises instead). Shorter than
    the lock, it is a mismatch on every run — never "run again to resume", which a server that
    ignores Range could not honour anyway.

    MUTATION: do not count a chunked body's end as the resource's (drop ``chunked or``) -> the
    first run asks to resume 1000 bytes the server will never add to -> RED (observed)."""
    state, asset = server
    state.mode, state.framing, state.honours_range = "small", "chunked", False
    staging = tmp_path / "dl"
    for _run in range(2):
        outcome = _download(asset, staging)
        assert "pinned 3072 bytes" in outcome and "deleted" in outcome, outcome
        assert "resume" not in outcome
        assert not (staging / "tool.zip.part").exists()
    assert state.ranges == [None, None]


def test_a_whole_answer_to_a_resume_without_a_length_is_final(
    server: tuple[_State, Asset], tmp_path: Path
) -> None:
    """A .part to resume, and a server that ignores Range and sends no Content-Length: it
    answers with the whole file again, ended only by closing the connection. Whether that body
    is complete cannot be told, but a later run could not resume it either — so a body short of
    the lock is a mismatch here, not a promise to resume.

    MUTATION: drop ``have > 0`` (a body without a length is final only when chunked) -> "run
    again to resume it", the .part kept -> RED (observed)."""
    state, asset = server
    state.mode, state.framing, state.honours_range = "small", "close", False
    staging = tmp_path / "dl"
    staging.mkdir()
    (staging / "tool.zip.part").write_bytes(SMALL[:500])
    outcome = _download(asset, staging)
    assert state.ranges == ["bytes=500-"]
    assert "pinned 3072 bytes" in outcome and "deleted" in outcome, outcome
    assert not (staging / "tool.zip.part").exists()


def test_a_body_without_a_length_cut_on_a_first_request_is_kept_and_resumed(
    server: tuple[_State, Asset], tmp_path: Path
) -> None:
    """The other side: no Content-Length, no chunks, and the connection drops. On a first request
    (no Range sent) the end of such a body may be a dropped connection, so it is kept, and the
    next run resumes it from a server that supports Range.

    MUTATION: count the end of any body without a length as final (``ends_at_eof = body is
    None``) -> the cut transfer is deleted as a mismatch -> RED (observed)."""
    state, asset = server
    state.mode, state.framing = "drop", "close"
    staging = tmp_path / "dl"
    outcome = _download(asset, staging)
    assert "run again to resume" in outcome, outcome
    assert (staging / "tool.zip.part").stat().st_size == DROP_AT
    state.mode = "ok"
    assert _download(asset, staging) == "ok"
    assert state.ranges == [None, f"bytes={DROP_AT}-"]
