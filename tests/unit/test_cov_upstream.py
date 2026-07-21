from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
from pathlib import Path
from typing import Any

import httpx
import pytest

from mcp_zero_trust_layer.config.models import ServerConfig
from mcp_zero_trust_layer.protocol import JSONRPCError
from mcp_zero_trust_layer.upstream.http import (
    HTTPUpstreamClient,
    _downstream_session,
    _read_response_content,
    _safe_error_body,
)
from mcp_zero_trust_layer.upstream.stdio import StdioProcessUpstream, _stdio_env

# ---------------------------------------------------------------------------
# http.py
# ---------------------------------------------------------------------------


def _serve(handler: type[BaseHTTPRequestHandler]) -> tuple[ThreadingHTTPServer, int]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, server.server_address[1]


class SessionHandler(BaseHTTPRequestHandler):
    seen_sessions: list[str | None] = []

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802
        self.__class__.seen_sessions.append(self.headers.get("mcp-session-id"))
        size = int(self.headers.get("content-length", "0"))
        message = json.loads(self.rfile.read(size))
        raw = json.dumps({"jsonrpc": "2.0", "id": message.get("id"), "result": {}}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.send_header("mcp-session-id", "sess-123")
        self.end_headers()
        self.wfile.write(raw)


class AcceptedHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802
        self.send_response(202)
        self.end_headers()


class NonJSONHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802
        raw = b"this is not json"
        self.send_response(200)
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class ArrayHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802
        raw = json.dumps([1, 2, 3]).encode()
        self.send_response(200)
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def test_http_send_requires_upstream() -> None:
    # A stdio server carries no upstream URL, so the HTTP client must fail closed.
    server = ServerConfig(name="stdio-srv", transport="stdio", command=["true"])
    with pytest.raises(JSONRPCError) as exc:
        HTTPUpstreamClient().send(server, {"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert exc.value.code == -32603


def test_http_session_id_is_cached_and_reused() -> None:
    SessionHandler.seen_sessions = []
    server, port = _serve(SessionHandler)
    try:
        config = ServerConfig(
            name="s", transport="http", upstream=f"http://127.0.0.1:{port}/mcp"
        )
        client = HTTPUpstreamClient()
        message = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        client.send(config, message)
        client.send(config, message)
    finally:
        server.shutdown()
    # First upstream call has no cached session, second reuses the captured one.
    assert SessionHandler.seen_sessions == [None, "sess-123"]


def test_http_accepted_returns_none() -> None:
    server, port = _serve(AcceptedHandler)
    try:
        config = ServerConfig(
            name="s", transport="http", upstream=f"http://127.0.0.1:{port}/mcp"
        )
        result = HTTPUpstreamClient().send(
            config, {"jsonrpc": "2.0", "id": 1, "method": "ping"}
        )
    finally:
        server.shutdown()
    assert result is None


def test_http_invalid_json_response() -> None:
    server, port = _serve(NonJSONHandler)
    try:
        config = ServerConfig(
            name="s", transport="http", upstream=f"http://127.0.0.1:{port}/mcp"
        )
        with pytest.raises(JSONRPCError) as exc:
            HTTPUpstreamClient().send(config, {"jsonrpc": "2.0", "id": 1, "method": "ping"})
    finally:
        server.shutdown()
    assert exc.value.code == -32603


def test_http_non_object_response() -> None:
    server, port = _serve(ArrayHandler)
    try:
        config = ServerConfig(
            name="s", transport="http", upstream=f"http://127.0.0.1:{port}/mcp"
        )
        with pytest.raises(JSONRPCError) as exc:
            HTTPUpstreamClient().send(config, {"jsonrpc": "2.0", "id": 1, "method": "ping"})
    finally:
        server.shutdown()
    assert exc.value.code == -32603


def test_http_timeout_maps_to_jsonrpc_error(monkeypatch) -> None:
    class _Client:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def __enter__(self) -> _Client:
            return self

        def __exit__(self, *args: Any) -> bool:
            return False

        def stream(self, *args: Any, **kwargs: Any) -> Any:
            raise httpx.TimeoutException("slow")

    monkeypatch.setattr(httpx, "Client", _Client)
    config = ServerConfig(name="s", transport="http", upstream="http://127.0.0.1:1/mcp")
    with pytest.raises(JSONRPCError) as exc:
        HTTPUpstreamClient().send(config, {"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert exc.value.code == -32002


def test_http_connection_error_maps_to_jsonrpc_error(monkeypatch) -> None:
    class _Client:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def __enter__(self) -> _Client:
            return self

        def __exit__(self, *args: Any) -> bool:
            return False

        def stream(self, *args: Any, **kwargs: Any) -> Any:
            raise httpx.ConnectError("refused")

    monkeypatch.setattr(httpx, "Client", _Client)
    config = ServerConfig(name="s", transport="http", upstream="http://127.0.0.1:1/mcp")
    with pytest.raises(JSONRPCError) as exc:
        HTTPUpstreamClient().send(config, {"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert exc.value.code == -32003


def test_downstream_session_reads_header() -> None:
    assert _downstream_session({"Mcp-Session-Id": "abc"}) == "abc"
    assert _downstream_session({"other": "x"}) == ""


class _FakeResponse:
    def __init__(self, headers: dict[str, str], chunks: list[bytes]) -> None:
        self.headers = headers
        self._chunks = chunks

    def iter_bytes(self) -> Any:
        return iter(self._chunks)


def test_read_response_content_ignores_invalid_content_length() -> None:
    config = ServerConfig(name="s", transport="http", upstream="http://x/mcp")
    response = _FakeResponse({"content-length": "not-a-number"}, [b"hi"])
    assert _read_response_content(response, config) == b"hi"  # type: ignore[arg-type]


def test_read_response_content_blocks_oversized_stream() -> None:
    config = ServerConfig(
        name="s", transport="http", upstream="http://x/mcp", max_response_bytes=4
    )
    response = _FakeResponse({}, [b"aa", b"bb", b"cc"])
    with pytest.raises(JSONRPCError) as exc:
        _read_response_content(response, config)  # type: ignore[arg-type]
    assert exc.value.code == -32032


def test_safe_error_body_decodes_non_json() -> None:
    assert _safe_error_body(b"plain text error") == "plain text error"


# ---------------------------------------------------------------------------
# stdio.py
# ---------------------------------------------------------------------------


def _echo_child(tmp_path: Path) -> Path:
    child = tmp_path / "echo.py"
    child.write_text(
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    msg = json.loads(line)\n"
        "    if 'id' in msg:\n"
        "        print(json.dumps({'jsonrpc':'2.0','id':msg['id'],'result':{'ok':True}}), flush=True)\n",
        encoding="utf-8",
    )
    return child


def _stdio_server(child: Path, **extra: Any) -> ServerConfig:
    return ServerConfig(
        name="echo",
        transport="stdio",
        command=[sys.executable, str(child)],
        **extra,
    )


def test_stdio_requires_command() -> None:
    http_server = ServerConfig(name="h", transport="http", upstream="http://x/mcp")
    with pytest.raises(JSONRPCError) as exc:
        StdioProcessUpstream(http_server)
    assert exc.value.code == -32603


def test_stdio_send_request_and_notification(tmp_path: Path) -> None:
    child = _echo_child(tmp_path)
    upstream = StdioProcessUpstream(_stdio_server(child))
    try:
        server = _stdio_server(child)
        # Notification (no id) returns None without waiting for a reply.
        assert upstream.send(server, {"jsonrpc": "2.0", "method": "notifications/x"}) is None
        response = upstream.send(
            server, {"jsonrpc": "2.0", "id": 1, "method": "ping"}
        )
        assert response == {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
    finally:
        upstream.close()


def test_stdio_send_fails_when_pipes_missing(tmp_path: Path) -> None:
    child = _echo_child(tmp_path)
    upstream = StdioProcessUpstream(_stdio_server(child))
    try:
        upstream.process.stdin = None  # type: ignore[assignment]
        with pytest.raises(JSONRPCError) as exc:
            upstream.send(_stdio_server(child), {"jsonrpc": "2.0", "id": 1, "method": "ping"})
        assert exc.value.code == -32603
    finally:
        upstream.close()


def test_stdio_send_detects_exited_process(tmp_path: Path) -> None:
    child = tmp_path / "exit.py"
    child.write_text("import sys\nsys.exit(0)\n", encoding="utf-8")
    upstream = StdioProcessUpstream(_stdio_server(child))
    try:
        for _ in range(50):
            if upstream.process.poll() is not None:
                break
            time.sleep(0.02)
        with pytest.raises(JSONRPCError) as exc:
            upstream.send(_stdio_server(child), {"jsonrpc": "2.0", "id": 1, "method": "ping"})
        assert exc.value.code == -32030
    finally:
        upstream.close()


def test_stdio_send_closed_stdout(tmp_path: Path) -> None:
    child = tmp_path / "readonly.py"
    # Reads a single line then exits, closing stdout (EOF) without replying.
    child.write_text(
        "import sys\nsys.stdin.readline()\n", encoding="utf-8"
    )
    upstream = StdioProcessUpstream(_stdio_server(child))
    try:
        with pytest.raises(JSONRPCError) as exc:
            upstream.send(_stdio_server(child), {"jsonrpc": "2.0", "id": 1, "method": "ping"})
        assert exc.value.code == -32030
    finally:
        upstream.close()


def test_stdio_send_invalid_json(tmp_path: Path) -> None:
    child = tmp_path / "garbage.py"
    child.write_text(
        "import sys\nsys.stdin.readline()\nprint('not json', flush=True)\n",
        encoding="utf-8",
    )
    upstream = StdioProcessUpstream(_stdio_server(child))
    try:
        with pytest.raises(JSONRPCError) as exc:
            upstream.send(_stdio_server(child), {"jsonrpc": "2.0", "id": 1, "method": "ping"})
        assert exc.value.code == -32603
    finally:
        upstream.close()


def test_stdio_send_non_object_response(tmp_path: Path) -> None:
    child = tmp_path / "array.py"
    child.write_text(
        "import sys\nsys.stdin.readline()\nprint('[1, 2, 3]', flush=True)\n",
        encoding="utf-8",
    )
    upstream = StdioProcessUpstream(_stdio_server(child))
    try:
        with pytest.raises(JSONRPCError) as exc:
            upstream.send(_stdio_server(child), {"jsonrpc": "2.0", "id": 1, "method": "ping"})
        assert exc.value.code == -32603
    finally:
        upstream.close()


def test_stdio_send_times_out(tmp_path: Path) -> None:
    child = tmp_path / "hang.py"
    child.write_text(
        "import sys, time\nsys.stdin.readline()\ntime.sleep(30)\n", encoding="utf-8"
    )
    upstream = StdioProcessUpstream(_stdio_server(child, timeout=0.2))
    try:
        with pytest.raises(JSONRPCError) as exc:
            upstream.send(_stdio_server(child), {"jsonrpc": "2.0", "id": 1, "method": "ping"})
        assert exc.value.code == -32002
    finally:
        upstream.close()


def test_stdio_close_kills_stuck_process(tmp_path: Path) -> None:
    child = _echo_child(tmp_path)
    upstream = StdioProcessUpstream(_stdio_server(child))

    class _StuckProcess:
        returncode = None

        def poll(self) -> None:
            return None

        def terminate(self) -> None:
            pass

        def wait(self, timeout: float | None = None) -> int:
            raise subprocess.TimeoutExpired(cmd="child", timeout=timeout or 0)

        def kill(self) -> None:
            self._killed = True

    real = upstream.process
    fake = _StuckProcess()
    upstream.process = fake  # type: ignore[assignment]
    upstream.close()
    assert getattr(fake, "_killed", False) is True
    # Clean up the real child we started.
    real.terminate()
    real.wait(timeout=2)


def test_stdio_pump_stderr(tmp_path: Path) -> None:
    child = tmp_path / "noisy.py"
    child.write_text(
        "import sys\n"
        "sys.stderr.write('warning line\\n')\n"
        "sys.stderr.flush()\n"
        "for line in sys.stdin:\n"
        "    msg = __import__('json').loads(line)\n"
        "    if 'id' in msg:\n"
        "        print(__import__('json').dumps({'jsonrpc':'2.0','id':msg['id'],'result':{}}), flush=True)\n",
        encoding="utf-8",
    )
    upstream = StdioProcessUpstream(_stdio_server(child))
    sink = StringIO()
    try:
        upstream.send(_stdio_server(child), {"jsonrpc": "2.0", "id": 1, "method": "ping"})
        upstream.close()
        upstream.pump_stderr(sink)
    finally:
        if upstream.process.poll() is None:
            upstream.close()
    assert "warning line" in sink.getvalue()


def test_stdio_pump_stderr_noop_when_missing(tmp_path: Path) -> None:
    child = _echo_child(tmp_path)
    upstream = StdioProcessUpstream(_stdio_server(child))
    try:
        upstream.process.stderr = None  # type: ignore[assignment]
        upstream.pump_stderr()
    finally:
        upstream.close()


def test_stdio_env_resolves_plain_values(tmp_path: Path) -> None:
    child = _echo_child(tmp_path)
    server = _stdio_server(child, env={"MCPZT_PLAIN": "value"})
    env = _stdio_env(server)
    assert env is not None
    assert env["MCPZT_PLAIN"] == "value"


def test_stdio_env_missing_secret_fails_closed(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("MCPZT_MISSING_STDIO_SECRET", raising=False)
    child = _echo_child(tmp_path)
    server = _stdio_server(child, env={"TOKEN": "env:MCPZT_MISSING_STDIO_SECRET"})
    with pytest.raises(JSONRPCError) as exc:
        _stdio_env(server)
    assert exc.value.code == -32031


def test_stdio_env_none_when_empty(tmp_path: Path) -> None:
    child = _echo_child(tmp_path)
    assert _stdio_env(_stdio_server(child)) is None
