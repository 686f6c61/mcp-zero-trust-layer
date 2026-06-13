from __future__ import annotations

import json
import sys
from io import StringIO
from pathlib import Path

from mcp_zero_trust_layer.transports.stdio import run_stdio_wrapper


def _write_child(path: Path, marker: Path | None = None) -> None:
    marker_line = f"Path({str(marker)!r}).write_text('called')\n" if marker else "pass\n"
    path.write_text(
        "import json\n"
        "import sys\n"
        "from pathlib import Path\n"
        "for line in sys.stdin:\n"
        "    msg = json.loads(line)\n"
        f"    {marker_line}"
        "    if 'id' in msg:\n"
        "        print(json.dumps({'jsonrpc':'2.0','id':msg['id'],'result':{'ok': True}}), flush=True)\n",
        encoding="utf-8",
    )


def _write_config(path: Path, child: Path, audit: Path) -> None:
    path.write_text(
        f"""
project:
  name: stdio-test
  environment: development

runtime:
  mode: stdio
  default_decision: deny

auth:
  mode: none

servers:
  - name: echo
    transport: stdio
    command:
      - {sys.executable}
      - {child}

capability_mappings:
  echo:
    tools:
      echo.allowed:
        action: echo.allowed
        risk: low
        access: read

policies:
  - id: allow-echo
    effect: allow
    match:
      server: echo
      action: echo.allowed

audit:
  destination: file
  path: {audit}
""",
        encoding="utf-8",
    )


def test_stdio_wrapper_forwards_allowed_call_without_logs_on_stdout(tmp_path: Path) -> None:
    child = tmp_path / "child.py"
    config = tmp_path / "mcpzt.yaml"
    audit = tmp_path / "audit.jsonl"
    _write_child(child)
    _write_config(config, child, audit)

    stdin = StringIO(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "echo.allowed", "arguments": {}},
            }
        )
        + "\n"
    )
    stdout = StringIO()
    stderr = StringIO()

    assert run_stdio_wrapper(config, server_name="echo", stdin=stdin, stdout=stdout, stderr=stderr) == 0

    lines = stdout.getvalue().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0]) == {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
    assert audit.exists()


def test_stdio_wrapper_denies_before_child_receives_call(tmp_path: Path) -> None:
    child = tmp_path / "child.py"
    marker = tmp_path / "called.txt"
    config = tmp_path / "mcpzt.yaml"
    audit = tmp_path / "audit.jsonl"
    _write_child(child, marker=marker)
    _write_config(config, child, audit)

    stdin = StringIO(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "echo.denied", "arguments": {}},
            }
        )
        + "\n"
    )
    stdout = StringIO()

    assert run_stdio_wrapper(config, server_name="echo", stdin=stdin, stdout=stdout) == 0

    response = json.loads(stdout.getvalue())
    assert response["error"]["code"] == -32001
    assert not marker.exists()
