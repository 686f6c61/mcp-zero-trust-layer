from __future__ import annotations

import json
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Annotated
from urllib.parse import urlparse

import typer
import yaml
from rich.console import Console
from rich.table import Table

from mcp_zero_trust_layer import __version__
from mcp_zero_trust_layer.approvals import ApprovalNotifier, ApprovalStore, create_approvals_app
from mcp_zero_trust_layer.audit import AuditLogger, search_audit_events, verify_audit_hash_chain
from mcp_zero_trust_layer.capabilities.discovery import (
    CapabilitySnapshot,
    default_snapshot_path,
    diff_snapshots,
    discover_capabilities,
    read_snapshot,
    write_snapshot,
)
from mcp_zero_trust_layer.capabilities.onboarding import (
    build_onboard_config,
    parse_server_specs,
)
from mcp_zero_trust_layer.client_import import import_client_config
from mcp_zero_trust_layer.config import load_config
from mcp_zero_trust_layer.config.models import MCPZTConfig, PolicyConfig, ServerConfig
from mcp_zero_trust_layer.config.secrets import (
    referenced_env_vars,
    referenced_secret_sources,
    secret_provider_available,
)
from mcp_zero_trust_layer.core import RequestContext
from mcp_zero_trust_layer.errors import ConfigError
from mcp_zero_trust_layer.identity import Identity
from mcp_zero_trust_layer.packs import add_pack, list_packs, read_pack
from mcp_zero_trust_layer.policy import (
    PolicyEngine,
    build_policy_coverage,
    find_policy_risks,
    find_unused_policies,
)
from mcp_zero_trust_layer.security import scan_snapshot
from mcp_zero_trust_layer.transports.http.server import run_http_server
from mcp_zero_trust_layer.transports.stdio import run_stdio_wrapper
from mcp_zero_trust_layer.upstream import UpstreamClient
from mcp_zero_trust_layer.upstream.http import HTTPUpstreamClient
from mcp_zero_trust_layer.upstream.stdio import StdioProcessUpstream

app = typer.Typer(help="MCP Zero Trust Layer")
config_app = typer.Typer(help="Configuration commands")
policy_app = typer.Typer(help="Policy commands")
audit_app = typer.Typer(help="Audit commands")
approve_app = typer.Typer(help="Approval commands")
pack_app = typer.Typer(help="Policy pack commands")
client_app = typer.Typer(help="MCP client configuration helpers")
app.add_typer(config_app, name="config")
app.add_typer(policy_app, name="policy")
app.add_typer(audit_app, name="audit")
app.add_typer(approve_app, name="approve")
app.add_typer(pack_app, name="pack")
app.add_typer(client_app, name="client")

console = Console()
CONFIG_FILENAME = "mcpzt.yaml"
DEFAULT_CONFIG_PATH = Path(CONFIG_FILENAME)
DEFAULT_CLIENT_IMPORT_DIR = Path(".mcpzt/client-import")
TABLE_JSON_FORMAT_ERROR = "[red]--format must be table or json[/red]"


DEFAULT_CONFIG = """project:
  name: example
  environment: development

runtime:
  mode: proxy
  default_decision: deny
  dry_run: false

auth:
  mode: none

servers:
  - name: github
    transport: http
    upstream: http://localhost:3001/mcp

capability_mappings:
  github:
    tools:
      github.search_issues:
        action: code.read
        risk: low
        access: read
        resource_type: issue
      github.merge_pull_request:
        action: code.merge
        risk: critical
        access: write
        resource_type: repository
        tags:
          - destructive
          - requires-human-review

policies:
  - id: github-read-only
    effect: allow
    match:
      server: github
      capability_type: tool
      capabilities:
        - github.search_issues
        - github.get_pull_request

  - id: critical-actions-need-approval
    effect: require_approval
    match:
      risk: critical

audit:
  destination: file
  path: ./mcpzt-audit.jsonl

approvals:
  backend: file
  path: ./mcpzt-approvals.json
  default_ttl_seconds: 900
"""


DEMO_FAKE_MCP = '''from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class DemoMCPHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802
        size = int(self.headers.get("content-length", "0"))
        message = json.loads(self.rfile.read(size))
        if "id" not in message:
            self.send_response(202)
            self.end_headers()
            return
        payload = self._response(message)
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _response(self, message: dict[str, Any]) -> dict[str, Any]:
        request_id = message.get("id")
        method = message.get("method")
        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "tools": [
                        {"name": "demo.safe_echo", "description": "Echo a short message."},
                        {
                            "name": "demo.delete_everything",
                            "description": "Dangerous demo action that policy denies.",
                        },
                        {
                            "name": "demo.get_customer",
                            "description": "Return a customer record with sensitive fields.",
                        },
                    ]
                },
            }
        if method == "tools/call":
            tool = message["params"]["name"]
            arguments = message["params"].get("arguments", {})
            if tool == "demo.safe_echo":
                return {"jsonrpc": "2.0", "id": request_id, "result": {"echo": arguments["message"]}}
            if tool == "demo.delete_everything":
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"content": [{"type": "text", "text": "this should not run"}]},
                }
            if tool == "demo.get_customer":
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "customer_id": arguments.get("customer_id", "cust_123"),
                        "name": "Ana",
                        "email": "ana@example.com",
                        "api_key": "sk-demo-secret",
                    },
                }
        return {"jsonrpc": "2.0", "id": request_id, "result": {}}


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 3001), DemoMCPHandler)
    print("fake MCP listening on http://127.0.0.1:3001/mcp", flush=True)
    server.serve_forever()
'''


DEMO_CONFIG = """project:
  name: mcpzt-demo
  environment: development

runtime:
  mode: gateway
  default_decision: deny

auth:
  mode: none

servers:
  - name: demo
    transport: http
    upstream: http://127.0.0.1:3001/mcp

capability_mappings:
  demo:
    tools:
      demo.safe_echo:
        action: demo.read
        risk: low
        access: read
      demo.delete_everything:
        action: demo.delete
        risk: critical
        access: delete
      demo.get_customer:
        action: crm.read
        risk: medium
        access: read
        data_classification: confidential

policies:
  - id: allow-demo-echo
    effect: allow
    match:
      server: demo
      capability: demo.safe_echo
    input:
      required_fields: [message]
      allowed_fields: [message]
      max_field_bytes:
        message: 120

  - id: deny-demo-delete
    effect: deny
    match:
      server: demo
      capability: demo.delete_everything

  - id: allow-demo-customer-read
    effect: allow
    match:
      server: demo
      capability: demo.get_customer
    input:
      required_fields: [customer_id]
      allowed_fields: [customer_id]

  - id: redact-demo-customer-secrets
    effect: redact
    match:
      server: demo
      capability: demo.get_customer
    when:
      output.email:
        exists: true
    output:
      redact_fields: [email, api_key]

audit:
  destination: file
  path: ./mcpzt-demo-audit.jsonl
  hash_chain: true

approvals:
  backend: file
  path: ./mcpzt-demo-approvals.json
"""


DEMO_CLIENT = '''from __future__ import annotations

import json
import sys
import urllib.request
from typing import Any


BASE_URL = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8765"


def rpc(request_id: int, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = json.dumps(
        {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}}
    ).encode("utf-8")
    request = urllib.request.Request(
        f"{BASE_URL}/mcp/demo",
        data=payload,
        method="POST",
        headers={"content-type": "application/json", "accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def call_tool(request_id: int, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return rpc(request_id, "tools/call", {"name": name, "arguments": arguments})


cases = {
    "visible tools": rpc(1, "tools/list"),
    "allowed echo": call_tool(2, "demo.safe_echo", {"message": "hello zero trust"}),
    "denied delete": call_tool(3, "demo.delete_everything", {}),
    "redacted customer": call_tool(4, "demo.get_customer", {"customer_id": "cust_123"}),
}

for title, payload in cases.items():
    print(f"\\n## {title}")
    print(json.dumps(payload, indent=2, sort_keys=True))
'''


DEMO_RUNNER = """#!/usr/bin/env sh
set -eu

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHON=${PYTHON:-python3}
MCPZT=${MCPZT:-mcpzt}
cd "$DIR"

cleanup() {
  if [ "${GATEWAY_PID:-}" ]; then kill "$GATEWAY_PID" 2>/dev/null || true; fi
  if [ "${UPSTREAM_PID:-}" ]; then kill "$UPSTREAM_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT INT TERM

"$PYTHON" fake_mcp.py &
UPSTREAM_PID=$!
sleep 1

"$MCPZT" run --config mcpzt.yaml --host 127.0.0.1 --port 8765 &
GATEWAY_PID=$!
sleep 2

"$PYTHON" demo_client.py http://127.0.0.1:8765
"""


DEMO_README = """# MCPZT Demo

This directory is generated by `mcpzt demo`.

Run the whole demo with:

```bash
./run_demo.sh
```

The script starts a fake HTTP MCP server, starts MCPZT in front of it, then sends four requests:

- `tools/list`, where the dangerous tool is hidden by policy.
- `demo.safe_echo`, which is allowed.
- `demo.delete_everything`, which is denied before the upstream sees it.
- `demo.get_customer`, which is allowed but returns redacted `email` and `api_key` fields.

The demo uses `auth.mode: none` so it can run without credentials. Real deployments should configure authentication and run `mcpzt doctor --strict --config mcpzt.yaml`.
"""


@app.command()
def version() -> None:
    """Show the installed MCP Zero Trust Layer version."""
    console.print(__version__)


@app.command()
def init(
    path: Annotated[Path, typer.Option("--config", "-c", help="Config file to create.")] = (
        DEFAULT_CONFIG_PATH
    ),
    force: Annotated[bool, typer.Option(help="Overwrite existing config.")] = False,
) -> None:
    """Create a starter versionable YAML config."""
    if path.exists() and not force:
        raise typer.BadParameter(f"{path} already exists; pass --force to overwrite")
    path.write_text(DEFAULT_CONFIG, encoding="utf-8")
    console.print(f"[green]Created[/green] {path}")


@app.command()
def demo(
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Directory where the demo files will be written."),
    ] = Path("mcpzt-demo"),
    force: Annotated[bool, typer.Option(help="Overwrite existing demo files.")] = False,
) -> None:
    """Create a runnable local demo with a fake MCP upstream."""
    files = {
        "fake_mcp.py": DEMO_FAKE_MCP,
        CONFIG_FILENAME: DEMO_CONFIG,
        "demo_client.py": DEMO_CLIENT,
        "run_demo.sh": DEMO_RUNNER,
        "README.md": DEMO_README,
    }
    if output.exists() and not force and any((output / name).exists() for name in files):
        raise typer.BadParameter(f"{output} already contains demo files; pass --force to overwrite")
    output.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        path = output / name
        path.write_text(content, encoding="utf-8")
        if name == "run_demo.sh":
            path.chmod(0o755)
    console.print(f"[green]Created demo[/green] {output}")
    console.print(f"Run it with: [bold]{output / 'run_demo.sh'}[/bold]")


@app.command()
def onboard(
    server: Annotated[
        list[str] | None,
        typer.Option(
            "--server",
            help="HTTP MCP upstream as name=url. Repeat for multiple upstreams.",
        ),
    ] = None,
    path: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Existing config to use as onboarding input."),
    ] = None,
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Generated config path."),
    ] = DEFAULT_CONFIG_PATH,
    force: Annotated[bool, typer.Option(help="Overwrite output config if it exists.")] = False,
    dry_run: Annotated[bool, typer.Option(help="Print generated config without writing files.")] = False,
    output_format: Annotated[
        str,
        typer.Option("--format", help="Report output format: table or json."),
    ] = "table",
    write_snapshots: Annotated[
        bool,
        typer.Option(help="Write discovery snapshots under --snapshot-dir."),
    ] = True,
    snapshot_dir: Annotated[
        Path,
        typer.Option(help="Directory for discovery snapshots."),
    ] = Path(".mcpzt-capabilities"),
) -> None:
    """Discover MCP servers and generate a conservative starter config."""
    try:
        base_config = _onboard_base_config(server or [], path)
        snapshots = _discover_configured_servers(base_config)
        result = build_onboard_config(base_config, snapshots)
    except (ConfigError, ValueError) as exc:
        console.print(f"[red]Cannot onboard:[/red] {exc}")
        raise typer.Exit(1) from exc

    _emit_onboard_config(
        result.config_yaml,
        snapshots=snapshots,
        output=output,
        force=force,
        dry_run=dry_run,
        write_snapshots=write_snapshots,
        snapshot_dir=snapshot_dir,
    )
    _emit_onboard_report(result.report.model_dump(mode="json"), result.report.model_dump_json(), output_format)


@config_app.command("validate")
def config_validate(
    path: Annotated[Path, typer.Option("--config", "-c")] = DEFAULT_CONFIG_PATH,
) -> None:
    """Validate configuration without starting a transport."""
    try:
        config = load_config(path)
    except ConfigError as exc:
        console.print(f"[red]Invalid config:[/red] {exc}")
        raise typer.Exit(1) from exc
    console.print(
        f"[green]Config valid[/green]: {config.project.name} "
        f"({config.project.environment}), {len(config.servers)} server(s), "
        f"{len(config.policies)} policy/policies"
    )


@config_app.command("schema")
def config_schema(
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
) -> None:
    """Print the JSON Schema for mcpzt.yaml."""
    schema = MCPZTConfig.model_json_schema()
    rendered = json.dumps(schema, indent=2, sort_keys=True)
    if output:
        output.write_text(rendered + "\n", encoding="utf-8")
        console.print(f"[green]Wrote[/green] {output}")
        return
    console.print(rendered)


@config_app.command("lint")
def config_lint(
    path: Annotated[Path, typer.Option("--config", "-c")] = DEFAULT_CONFIG_PATH,
    output_format: Annotated[
        str,
        typer.Option("--format", help="Output format: table or json."),
    ] = "table",
    strict: Annotated[bool, typer.Option(help="Exit non-zero when warnings are present.")] = False,
) -> None:
    """Report insecure or fragile configuration patterns."""
    try:
        config = load_config(path)
    except ConfigError as exc:
        console.print(f"[red]Cannot lint config:[/red] {exc}")
        raise typer.Exit(1) from exc
    findings = _lint_config(config)
    if output_format == "json":
        console.print_json(json.dumps(findings))
    elif output_format == "table":
        _print_lint_table(findings)
    else:
        console.print(TABLE_JSON_FORMAT_ERROR)
        raise typer.Exit(1)

    has_errors = any(finding["severity"] == "error" for finding in findings)
    has_warnings = any(finding["severity"] == "warning" for finding in findings)
    if has_errors or (strict and has_warnings):
        raise typer.Exit(1)


@policy_app.command("test")
def policy_test(
    server: Annotated[str, typer.Option(help="Logical MCP server name.")],
    method: Annotated[str, typer.Option(help="MCP method, e.g. tools/call.")],
    capability: Annotated[str | None, typer.Option(help="Capability name.")] = None,
    capability_type: Annotated[
        str, typer.Option(help="tool, resource, prompt, or method.")
    ] = "tool",
    arguments: Annotated[
        str, typer.Option("--arguments", "-a", help="JSON object with call arguments.")
    ] = "{}",
    config_path: Annotated[Path, typer.Option("--config", "-c")] = DEFAULT_CONFIG_PATH,
    subject: Annotated[str, typer.Option(help="Identity subject for the simulation.")] = "local",
    client_id: Annotated[str | None, typer.Option(help="Client id for the simulation.")] = None,
    agent_id: Annotated[str | None, typer.Option(help="Agent id for the simulation.")] = None,
) -> None:
    """Evaluate a simulated MCP request against policies."""
    try:
        config, context = _policy_context(
            config_path=config_path,
            server=server,
            method=method,
            capability=capability,
            capability_type=capability_type,
            arguments=arguments,
            subject=subject,
            client_id=client_id,
            agent_id=agent_id,
        )
    except (ConfigError, json.JSONDecodeError) as exc:
        console.print(f"[red]Cannot run policy test:[/red] {exc}")
        raise typer.Exit(1) from exc
    decision = PolicyEngine(config).evaluate(context)
    console.print_json(decision.model_dump_json())


@policy_app.command("explain")
def policy_explain(
    server: Annotated[str, typer.Option(help="Logical MCP server name.")],
    method: Annotated[str, typer.Option(help="MCP method, e.g. tools/call.")],
    capability: Annotated[str | None, typer.Option(help="Capability name.")] = None,
    capability_type: Annotated[
        str, typer.Option(help="tool, resource, prompt, or method.")
    ] = "tool",
    arguments: Annotated[
        str, typer.Option("--arguments", "-a", help="JSON object with call arguments.")
    ] = "{}",
    config_path: Annotated[Path, typer.Option("--config", "-c")] = DEFAULT_CONFIG_PATH,
    subject: Annotated[str, typer.Option(help="Identity subject for the simulation.")] = "local",
    client_id: Annotated[str | None, typer.Option(help="Client id for the simulation.")] = None,
    agent_id: Annotated[str | None, typer.Option(help="Agent id for the simulation.")] = None,
) -> None:
    """Explain why policies match or do not match a simulated MCP request."""
    try:
        config, context = _policy_context(
            config_path=config_path,
            server=server,
            method=method,
            capability=capability,
            capability_type=capability_type,
            arguments=arguments,
            subject=subject,
            client_id=client_id,
            agent_id=agent_id,
        )
    except (ConfigError, json.JSONDecodeError) as exc:
        console.print(f"[red]Cannot explain policy:[/red] {exc}")
        raise typer.Exit(1) from exc
    console.print_json(json.dumps(PolicyEngine(config).explain(context)))


@policy_app.command("coverage")
def policy_coverage(
    path: Annotated[Path, typer.Option("--config", "-c")] = DEFAULT_CONFIG_PATH,
    snapshot: Annotated[
        Path | None,
        typer.Option(help="Optional discovered capability snapshot to evaluate."),
    ] = None,
    output_format: Annotated[
        str,
        typer.Option("--format", help="Output format: table or json."),
    ] = "table",
) -> None:
    """Show how mapped or discovered capabilities resolve through policy."""
    try:
        config = load_config(path)
        report = build_policy_coverage(
            config,
            snapshot=read_snapshot(snapshot) if snapshot else None,
        )
    except (ConfigError, ValueError) as exc:
        console.print(f"[red]Cannot build policy coverage:[/red] {exc}")
        raise typer.Exit(1) from exc
    if output_format == "json":
        console.print_json(report.model_dump_json())
        return
    if output_format != "table":
        console.print(TABLE_JSON_FORMAT_ERROR)
        raise typer.Exit(1)
    _print_policy_coverage_table(report.model_dump(mode="json")["items"])


@policy_app.command("risks")
def policy_risks(
    path: Annotated[Path, typer.Option("--config", "-c")] = DEFAULT_CONFIG_PATH,
    snapshot: Annotated[
        Path | None,
        typer.Option(help="Optional discovered capability snapshot to evaluate."),
    ] = None,
    output_format: Annotated[
        str,
        typer.Option("--format", help="Output format: table or json."),
    ] = "table",
) -> None:
    """Report policy coverage risks for mapped or discovered capabilities."""
    try:
        config = load_config(path)
        report = find_policy_risks(
            config,
            snapshot=read_snapshot(snapshot) if snapshot else None,
        )
    except (ConfigError, ValueError) as exc:
        console.print(f"[red]Cannot analyze policy risks:[/red] {exc}")
        raise typer.Exit(1) from exc
    if output_format == "json":
        console.print_json(report.model_dump_json())
        return
    if output_format != "table":
        console.print(TABLE_JSON_FORMAT_ERROR)
        raise typer.Exit(1)
    _print_policy_risks_table(report.model_dump(mode="json")["findings"])
    if report.failed:
        raise typer.Exit(2)


@policy_app.command("unused")
def policy_unused(
    path: Annotated[Path, typer.Option("--config", "-c")] = DEFAULT_CONFIG_PATH,
    snapshot: Annotated[
        Path | None,
        typer.Option(help="Optional discovered capability snapshot to evaluate."),
    ] = None,
    output_format: Annotated[
        str,
        typer.Option("--format", help="Output format: table or json."),
    ] = "table",
) -> None:
    """Find policies that do not structurally match known capabilities."""
    try:
        config = load_config(path)
        report = find_unused_policies(
            config,
            snapshot=read_snapshot(snapshot) if snapshot else None,
        )
    except (ConfigError, ValueError) as exc:
        console.print(f"[red]Cannot analyze unused policies:[/red] {exc}")
        raise typer.Exit(1) from exc
    if output_format == "json":
        console.print_json(report.model_dump_json())
        return
    if output_format != "table":
        console.print(TABLE_JSON_FORMAT_ERROR)
        raise typer.Exit(1)
    _print_unused_policies_table(report.model_dump(mode="json")["policies"])


@app.command()
def run(
    path: Annotated[Path, typer.Option("--config", "-c")] = DEFAULT_CONFIG_PATH,
    host: Annotated[str, typer.Option(help="Host for the HTTP proxy.")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Port for the HTTP proxy.")] = 8765,
    server: Annotated[str | None, typer.Option(help="Default logical server for /mcp.")] = None,
) -> None:
    """Run the HTTP/gateway transport."""
    config = load_config(path)
    if not any(item.transport == "http" for item in config.servers):
        console.print("[red]No HTTP servers configured.[/red]")
        raise typer.Exit(1)
    console.print(
        f"[green]Starting MCP Zero Trust Layer[/green] on http://{host}:{port}/mcp "
        f"with {len(config.servers)} configured server(s)."
    )
    run_http_server(path, host=host, port=port, server=server)


@app.command()
def wrap(
    path: Annotated[Path, typer.Option("--config", "-c")] = DEFAULT_CONFIG_PATH,
    server: Annotated[str | None, typer.Option(help="Logical stdio server to wrap.")] = None,
) -> None:
    """Wrap a stdio MCP server behind policy enforcement."""
    config = load_config(path)
    matching = [item for item in config.servers if item.transport == "stdio"]
    if server:
        matching = [item for item in matching if item.name == server]
    if not matching:
        console.print("[red]No matching stdio server configured.[/red]")
        raise typer.Exit(1)
    raise typer.Exit(run_stdio_wrapper(path, server_name=server))


@app.command()
def discover(
    server: Annotated[str, typer.Option(help="Logical server to discover.")],
    path: Annotated[Path, typer.Option("--config", "-c")] = DEFAULT_CONFIG_PATH,
    output: Annotated[Path | None, typer.Option(help="Snapshot output path.")] = None,
) -> None:
    """Discover upstream capabilities."""
    config = load_config(path)
    selected = _server(config, server)
    upstream = _upstream_for(selected)
    try:
        snapshot = discover_capabilities(config, server, upstream)
    finally:
        if hasattr(upstream, "close"):
            upstream.close()  # type: ignore[attr-defined]
    output = output or default_snapshot_path(server)
    write_snapshot(snapshot, output)
    console.print(f"[green]Wrote capability snapshot[/green] {output}")
    console.print_json(snapshot.model_dump_json())


@app.command()
def diff(
    server: Annotated[str, typer.Option(help="Logical server to diff.")],
    path: Annotated[Path, typer.Option("--config", "-c")] = DEFAULT_CONFIG_PATH,
    snapshot: Annotated[Path | None, typer.Option(help="Previous snapshot path.")] = None,
) -> None:
    """Compare upstream capabilities against a snapshot."""
    config = load_config(path)
    selected = _server(config, server)
    snapshot = snapshot or default_snapshot_path(server)
    previous = read_snapshot(snapshot)
    upstream = _upstream_for(selected)
    try:
        current = discover_capabilities(config, server, upstream)
    finally:
        if hasattr(upstream, "close"):
            upstream.close()  # type: ignore[attr-defined]
    capability_diff = diff_snapshots(previous, current)
    console.print_json(capability_diff.model_dump_json())
    if capability_diff.has_changes():
        raise typer.Exit(2)


@app.command()
def scan(
    path: Annotated[Path, typer.Option("--config", "-c")] = DEFAULT_CONFIG_PATH,
    server: Annotated[
        str | None,
        typer.Option(help="Logical server to discover live when --snapshot is not provided."),
    ] = None,
    snapshot: Annotated[Path | None, typer.Option(help="Capability snapshot to scan.")] = None,
) -> None:
    """Run deterministic security checks against discovered MCP capabilities."""
    try:
        config = load_config(path)
        if snapshot:
            capability_snapshot = read_snapshot(snapshot)
        else:
            if not server:
                raise ValueError("scan requires --server or --snapshot")
            selected = _server(config, server)
            upstream = _upstream_for(selected)
            try:
                capability_snapshot = discover_capabilities(config, server, upstream)
            finally:
                if hasattr(upstream, "close"):
                    upstream.close()  # type: ignore[attr-defined]
        report = scan_snapshot(config, capability_snapshot)
    except (ConfigError, ValueError) as exc:
        console.print(f"[red]Cannot scan:[/red] {exc}")
        raise typer.Exit(1) from exc

    console.print_json(report.model_dump_json())
    if report.failed:
        raise typer.Exit(2)


@audit_app.command("tail")
def audit_tail(
    path: Annotated[Path, typer.Option("--config", "-c")] = DEFAULT_CONFIG_PATH,
    lines: Annotated[int, typer.Option("--lines", "-n", help="Number of events to show.")] = 20,
) -> None:
    """Tail audit events."""
    config = load_config(path)
    if config.audit.destination != "file":
        console.print("[red]audit tail requires audit.destination: file[/red]")
        raise typer.Exit(1)
    audit_path = Path(config.audit.path)
    if not audit_path.exists():
        console.print(f"[yellow]No audit file yet:[/yellow] {audit_path}")
        return
    events = audit_path.read_text(encoding="utf-8").splitlines()[-lines:]
    for event in events:
        console.print(event)


@audit_app.command("verify")
def audit_verify(
    path: Annotated[Path, typer.Option("--config", "-c")] = DEFAULT_CONFIG_PATH,
    audit_path: Annotated[
        Path | None,
        typer.Option("--audit-path", help="Override the configured audit JSONL path."),
    ] = None,
) -> None:
    """Verify the audit hash chain."""
    config = load_config(path)
    if config.audit.destination != "file" and audit_path is None:
        console.print("[red]audit verify requires a file audit path[/red]")
        raise typer.Exit(1)
    target = audit_path or Path(config.audit.path)
    ok, message = verify_audit_hash_chain(target)
    if ok:
        console.print(f"[green]OK[/green] {message}")
        return
    console.print(f"[red]FAIL[/red] {message}")
    raise typer.Exit(1)


@audit_app.command("search")
def audit_search(
    path: Annotated[Path, typer.Option("--config", "-c")] = DEFAULT_CONFIG_PATH,
    output_format: Annotated[
        str,
        typer.Option("--format", help="Output format: table or json."),
    ] = "table",
    event_type: Annotated[str | None, typer.Option(help="Filter by event_type.")] = None,
    server: Annotated[str | None, typer.Option(help="Filter by logical server.")] = None,
    decision: Annotated[str | None, typer.Option(help="Filter by policy decision.")] = None,
    policy_id: Annotated[str | None, typer.Option(help="Filter by selected policy id.")] = None,
    correlation_id: Annotated[
        str | None,
        typer.Option(help="Filter by audit correlation id."),
    ] = None,
    approval_id: Annotated[str | None, typer.Option(help="Filter by approval id.")] = None,
    since: Annotated[
        str | None,
        typer.Option(help="Only include events at or after this ISO timestamp."),
    ] = None,
    until: Annotated[
        str | None,
        typer.Option(help="Only include events at or before this ISO timestamp."),
    ] = None,
    limit: Annotated[int, typer.Option(help="Maximum matching events to return.")] = 100,
) -> None:
    """Search audit events by operational fields."""
    config = load_config(path)
    if config.audit.destination != "file":
        console.print("[red]audit search requires audit.destination: file[/red]")
        raise typer.Exit(1)
    try:
        events = search_audit_events(
            config.audit.path,
            event_type=event_type,
            server=server,
            decision=decision,
            policy_id=policy_id,
            correlation_id=correlation_id,
            approval_id=approval_id,
            since=_parse_cli_timestamp(since),
            until=_parse_cli_timestamp(until),
            limit=limit,
        )
    except ValueError as exc:
        console.print(f"[red]Cannot search audit:[/red] {exc}")
        raise typer.Exit(1) from exc

    if output_format == "json":
        console.print_json(json.dumps(events))
        return
    if output_format != "table":
        console.print(TABLE_JSON_FORMAT_ERROR)
        raise typer.Exit(1)
    _print_audit_search_table(events)


@approve_app.command("list")
def approve_list(
    path: Annotated[Path, typer.Option("--config", "-c")] = DEFAULT_CONFIG_PATH,
    output_format: Annotated[
        str,
        typer.Option("--format", help="Output format: table or json."),
    ] = "table",
) -> None:
    """List pending approvals."""
    config = load_config(path)
    approvals = ApprovalStore(config.approvals).list()
    if output_format == "json":
        payload = [approval.model_dump(mode="json") for approval in approvals]
        console.print_json(json.dumps(payload))
        return
    if output_format != "table":
        console.print(TABLE_JSON_FORMAT_ERROR)
        raise typer.Exit(1)
    table = Table(expand=False)
    table.add_column("ID", no_wrap=True, overflow="ignore")
    table.add_column("Status", no_wrap=True)
    table.add_column("Server", no_wrap=True)
    table.add_column("Capability", overflow="fold")
    table.add_column("Policy", overflow="fold")
    table.add_column("Subject", overflow="fold")
    table.add_column("Expires", no_wrap=True)
    for approval in approvals:
        table.add_row(
            approval.id,
            approval.status,
            approval.server,
            approval.capability or "",
            approval.policy_id,
            approval.identity_subject,
            approval.expires_at.isoformat() if approval.expires_at else "",
        )
    Console(width=180).print(table)


@approve_app.command("show")
def approve_show(
    approval_id: str,
    path: Annotated[Path, typer.Option("--config", "-c")] = DEFAULT_CONFIG_PATH,
) -> None:
    """Show one approval request."""
    config = load_config(path)
    approval = ApprovalStore(config.approvals).get(approval_id)
    if not approval:
        console.print(f"[red]Approval not found:[/red] {approval_id}")
        raise typer.Exit(1)
    console.print_json(approval.model_dump_json())


@approve_app.command("allow")
def approve_allow(
    approval_id: str,
    path: Annotated[Path, typer.Option("--config", "-c")] = DEFAULT_CONFIG_PATH,
    decided_by: Annotated[
        str | None,
        typer.Option("--by", help="Approver identity to store in the decision."),
    ] = None,
    comment: Annotated[
        str | None,
        typer.Option("--comment", help="Optional decision comment."),
    ] = None,
) -> None:
    """Approve a pending request."""
    _set_approval_status(path, approval_id, "approved", decided_by=decided_by, comment=comment)


@approve_app.command("deny")
def approve_deny(
    approval_id: str,
    path: Annotated[Path, typer.Option("--config", "-c")] = DEFAULT_CONFIG_PATH,
    decided_by: Annotated[
        str | None,
        typer.Option("--by", help="Approver identity to store in the decision."),
    ] = None,
    comment: Annotated[
        str | None,
        typer.Option("--comment", help="Optional decision comment."),
    ] = None,
) -> None:
    """Deny a pending request."""
    _set_approval_status(path, approval_id, "denied", decided_by=decided_by, comment=comment)


@approve_app.command("serve")
def approve_serve(
    path: Annotated[Path, typer.Option("--config", "-c")] = DEFAULT_CONFIG_PATH,
    host: Annotated[str, typer.Option(help="Host for the approval UI.")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Port for the approval UI.")] = 8770,
) -> None:
    """Run the self-hosted approval review UI."""
    import uvicorn

    config = load_config(path)
    console.print(f"[green]Starting approval UI[/green] on http://{host}:{port}")
    uvicorn.run(create_approvals_app(config), host=host, port=port)


@pack_app.command("list")
def pack_list() -> None:
    """List bundled policy packs."""
    for pack in list_packs():
        console.print(pack)


@pack_app.command("show")
def pack_show(name: str) -> None:
    """Print a bundled policy pack."""
    try:
        console.print(read_pack(name))
    except KeyError as exc:
        console.print(f"[red]Unknown pack:[/red] {name}")
        raise typer.Exit(1) from exc


@pack_app.command("add")
def pack_add(name: str, output: Annotated[Path, typer.Option("--output", "-o")]) -> None:
    """Write a bundled policy pack to a local file."""
    try:
        target = add_pack(name, output)
    except KeyError as exc:
        console.print(f"[red]Unknown pack:[/red] {name}")
        raise typer.Exit(1) from exc
    console.print(f"[green]Wrote[/green] {target}")


@client_app.command("config")
def client_config(
    kind: Annotated[
        str,
        typer.Option(
            "--kind",
            "-k",
            help=(
                "claude-desktop, cursor, vscode, claude-code, or json. "
                "Use json for machine-readable output; claude-code emits CLI commands."
            ),
        ),
    ] = "claude-desktop",
    path: Annotated[Path, typer.Option("--config", "-c")] = DEFAULT_CONFIG_PATH,
    base_url: Annotated[
        str,
        typer.Option("--base-url", help="Public base URL where MCPZT is reachable."),
    ] = "http://127.0.0.1:8765",
    server: Annotated[str | None, typer.Option(help="Only generate one logical server.")] = None,
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
) -> None:
    """Generate MCP client configuration that points clients at MCPZT."""
    try:
        config = load_config(path)
        rendered = _render_client_config(config, kind, base_url=base_url, server_name=server)
    except (ConfigError, ValueError) as exc:
        console.print(f"[red]Cannot generate client config:[/red] {exc}")
        raise typer.Exit(1) from exc
    if output:
        output.write_text(rendered + "\n", encoding="utf-8")
        console.print(f"[green]Wrote[/green] {output}")
        return
    console.print(rendered)


@client_app.command("import")
def client_import(
    source: Annotated[
        Path | None,
        typer.Option(
            "--source",
            help="Existing MCP client JSON config. Defaults to Claude Desktop on macOS.",
        ),
    ] = None,
    mcpzt_config: Annotated[
        Path,
        typer.Option("--mcpzt-config", help="Output MCPZT YAML config."),
    ] = DEFAULT_CLIENT_IMPORT_DIR / CONFIG_FILENAME,
    client_output: Annotated[
        Path,
        typer.Option("--client-output", help="Output wrapped client JSON config."),
    ] = DEFAULT_CLIENT_IMPORT_DIR / "claude_desktop_config.mcpzt.json",
    base_url: Annotated[
        str,
        typer.Option("--base-url", help="MCPZT HTTP gateway base URL for imported HTTP servers."),
    ] = "http://127.0.0.1:8765",
    wrapper_command: Annotated[
        str,
        typer.Option(
            "--wrapper-command",
            help="Command the client should run for imported stdio servers.",
        ),
    ] = "mcpzt",
    project_name: Annotated[
        str,
        typer.Option("--project-name", help="Project name for the generated MCPZT config."),
    ] = "mcpzt-imported-client",
    discover: Annotated[
        bool,
        typer.Option(help="Discover real upstream capabilities and generate starter policies."),
    ] = False,
    snapshot_dir: Annotated[
        Path | None,
        typer.Option(
            "--snapshot-dir",
            help="Directory for discovered capability snapshots when --discover is used.",
        ),
    ] = None,
    force: Annotated[bool, typer.Option(help="Overwrite generated files.")] = False,
) -> None:
    """Import an existing Claude/Cursor/VS Code MCP config and wrap it with MCPZT."""
    source_path = (source or _default_claude_desktop_config()).expanduser()
    mcpzt_config = mcpzt_config.expanduser()
    client_output = client_output.expanduser()
    for output in [mcpzt_config, client_output]:
        if output.exists() and not force:
            raise typer.BadParameter(f"{output} already exists; pass --force to overwrite")
    try:
        imported = import_client_config(
            source_path,
            project_name=project_name,
            audit_path=str((mcpzt_config.parent / "audit.jsonl").resolve()),
            approvals_path=str((mcpzt_config.parent / "approvals.sqlite3").resolve()),
            base_url=base_url,
            wrapper_command=wrapper_command,
            mcpzt_config_path=mcpzt_config.resolve(),
        )
        config_yaml = imported.mcpzt_config_yaml
        report: object | None = None
        if discover:
            base_config = MCPZTConfig.model_validate(yaml.safe_load(config_yaml))
            snapshots = _discover_configured_servers(base_config)
            result = build_onboard_config(base_config, snapshots)
            config_yaml = result.config_yaml
            report = result.report
            target_snapshot_dir = (snapshot_dir or (mcpzt_config.parent / "capabilities")).expanduser()
            _write_onboard_snapshots(
                snapshots,
                write_snapshots=True,
                snapshot_dir=target_snapshot_dir,
            )
    except (ConfigError, OSError, ValueError) as exc:
        console.print(f"[red]Cannot import client config:[/red] {exc}")
        raise typer.Exit(1) from exc

    mcpzt_config.parent.mkdir(parents=True, exist_ok=True)
    client_output.parent.mkdir(parents=True, exist_ok=True)
    mcpzt_config.write_text(config_yaml, encoding="utf-8")
    client_output.write_text(imported.client_config_json + "\n", encoding="utf-8")
    console.print(f"[green]Wrote MCPZT config[/green] {mcpzt_config}")
    console.print(f"[green]Wrote wrapped client config[/green] {client_output}")
    if discover:
        console.print(
            f"[green]Wrote discovery snapshots[/green] "
            f"{snapshot_dir or (mcpzt_config.parent / 'capabilities')}"
        )
    _print_imported_servers(imported.servers)
    if report is not None:
        _print_onboard_report(report.model_dump(mode="json"))  # type: ignore[attr-defined]


@app.command()
def doctor(
    path: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    strict: Annotated[bool, typer.Option(help="Exit non-zero when warnings are present.")] = False,
    production: Annotated[
        bool,
        typer.Option(help="Require the loaded config to use production posture."),
    ] = False,
) -> None:
    """Diagnose local environment and optional MCPZT config."""
    checks: list[tuple[str, str, str]] = []
    _doctor_add(checks, "OK", "package", f"mcp-zero-trust-layer {__version__} importable")
    config: MCPZTConfig | None = None

    if path is None:
        status = "FAIL" if production else "WARN"
        _doctor_add(checks, status, "config", "pass --config to validate a project config")
    else:
        try:
            config = load_config(path)
        except ConfigError as exc:
            _doctor_add(checks, "FAIL", "config", str(exc))
        else:
            if production and config.project.environment != "production":
                _doctor_add(
                    checks,
                    "FAIL",
                    "config",
                    f"--production requires project.environment: production, got "
                    f"{config.project.environment}",
                )
            _doctor_add(
                checks,
                "OK",
                "config",
                f"{config.project.name} ({config.project.environment}) with "
                f"{len(config.servers)} server(s)",
            )
            _doctor_config(checks, config)

    table = Table("Status", "Check", "Details")
    for status, check, details in checks:
        style = {"OK": "green", "WARN": "yellow", "FAIL": "red"}[status]
        table.add_row(f"[{style}]{status}[/{style}]", check, details)
    console.print(table)

    if any(status == "FAIL" for status, _, _ in checks) or (
        strict and any(status == "WARN" for status, _, _ in checks)
    ):
        raise typer.Exit(1)


def _lint_config(config: MCPZTConfig) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    _lint_runtime(config, findings)
    _lint_auth(config, findings)
    _lint_servers(config, findings)
    _lint_policies(config, findings)
    _lint_capability_mappings(config, findings)
    _lint_state(config, findings)
    return findings


def _lint_runtime(config: MCPZTConfig, findings: list[dict[str, str]]) -> None:
    if config.runtime.default_decision == "allow":
        _lint_add(
            findings,
            "warning",
            "runtime.default_decision",
            "runtime.default_decision is allow",
            "Use default_decision: deny and add explicit allow policies.",
        )
    if config.runtime.dry_run:
        severity = "error" if config.project.environment == "production" else "warning"
        _lint_add(
            findings,
            severity,
            "runtime.dry_run",
            "runtime.dry_run is enabled",
            "Use dry_run only while learning policy impact.",
        )
    if config.runtime.allow_auth_none_in_production:
        _lint_add(
            findings,
            "warning",
            "runtime.allow_auth_none_in_production",
            "production auth-none override is enabled",
            "Remove this override before public or shared deployments.",
        )
    if config.runtime.allow_dry_run_in_production:
        _lint_add(
            findings,
            "warning",
            "runtime.allow_dry_run_in_production",
            "production dry-run override is enabled",
            "Remove this override before relying on enforcement.",
        )
    if config.project.environment == "production" and not config.runtime.allowed_origins:
        _lint_add(
            findings,
            "warning",
            "runtime.allowed_origins",
            "production config has no allowed Origin list",
            "Set runtime.allowed_origins when browser-based clients can reach MCPZT.",
        )


def _lint_auth(config: MCPZTConfig, findings: list[dict[str, str]]) -> None:
    if config.auth.mode == "none":
        severity = "error" if config.project.environment == "production" else "warning"
        _lint_add(
            findings,
            severity,
            "auth.mode",
            "auth.mode is none",
            "Use static_token, api_key, jwt or oidc before sharing MCPZT.",
        )
    inline_token = _auth_inline_token(config)
    if inline_token:
        severity = "error" if inline_token in {"change-me", "changeme", "secret"} else "warning"
        _lint_add(
            findings,
            severity,
            "auth.token",
            "auth.token is inline",
            "Use auth.token_env or an env:/file:/secret-manager reference.",
        )
    if config.project.environment == "production" and config.auth.trust_identity_headers:
        _lint_add(
            findings,
            "warning",
            "auth.trust_identity_headers",
            "production trusts caller identity headers",
            "Only enable this behind a trusted gateway that strips spoofed x-mcpzt-* headers.",
        )
    if config.project.environment == "production" and config.auth.mode in {"jwt", "oidc"}:
        if not config.auth.required_scopes:
            _lint_add(
                findings,
                "warning",
                "auth.required_scopes",
                "JWT/OIDC auth has no required scopes",
                "Require at least one MCPZT-specific scope for production clients.",
            )


def _lint_servers(config: MCPZTConfig, findings: list[dict[str, str]]) -> None:
    for server in config.servers:
        for header, value in server.upstream_headers.items():
            if _looks_sensitive_header(header) and not referenced_secret_sources(value):
                _lint_add(
                    findings,
                    "warning",
                    f"servers.{server.name}.upstream_headers.{header}",
                    "sensitive upstream header is inline",
                    "Use env:, ${VAR}, file: or a secret-manager reference.",
                )
        if (
            config.project.environment == "production"
            and server.transport == "http"
            and server.upstream
            and server.upstream.startswith("http://")
            and "127.0.0.1" not in server.upstream
            and "localhost" not in server.upstream
        ):
            _lint_add(
                findings,
                "warning",
                f"servers.{server.name}.upstream",
                "production upstream uses plain HTTP",
                "Use HTTPS unless the upstream is same-host or protected by private networking.",
            )


def _lint_policies(config: MCPZTConfig, findings: list[dict[str, str]]) -> None:
    for policy in config.policies:
        if policy.effect == "allow" and _policy_match_is_empty(policy):
            _lint_add(
                findings,
                "warning",
                f"policies.{policy.id}",
                "allow policy has an empty match block",
                "Constrain allow policies by server, capability, action, risk or identity.",
            )
        if policy.effect == "allow" and policy.match.risk in {"high", "critical"}:
            _lint_add(
                findings,
                "warning",
                f"policies.{policy.id}",
                f"allow policy directly matches {policy.match.risk} risk",
                "Prefer require_approval or add narrow capability and validator constraints.",
            )
        if (
            policy.effect == "allow"
            and not policy.input
            and not policy.validators
            and not (policy.match.capability or policy.match.capabilities)
            and policy.match.action
        ):
            _lint_add(
                findings,
                "warning",
                f"policies.{policy.id}",
                "semantic allow policy has no call-time constraints",
                "Consider input.allowed_fields, input.required_fields or validators for tools/call.",
            )


def _lint_capability_mappings(config: MCPZTConfig, findings: list[dict[str, str]]) -> None:
    for server_name, mappings in config.capability_mappings.items():
        for kind, capabilities in [
            ("tools", mappings.tools),
            ("resources", mappings.resources),
            ("prompts", mappings.prompts),
        ]:
            for capability, metadata in capabilities.items():
                if not any(
                    [
                        metadata.action,
                        metadata.risk,
                        metadata.access,
                        metadata.resource_type,
                        metadata.tags,
                        metadata.data_classification,
                        metadata.owner,
                    ]
                ):
                    _lint_add(
                        findings,
                        "warning",
                        f"capability_mappings.{server_name}.{kind}.{capability}",
                        "capability metadata is empty",
                        "Add action, risk, access, owner or data classification metadata.",
                    )


def _lint_state(config: MCPZTConfig, findings: list[dict[str, str]]) -> None:
    if config.approvals.backend == "sqlite" and Path(config.approvals.path).suffix == ".json":
        _lint_add(
            findings,
            "warning",
            "approvals.path",
            "sqlite approval backend uses a JSON-looking path",
            "Use a .sqlite3 or .db path to make the approval backend obvious.",
        )
    if config.approvals.default_ttl_seconds <= 0:
        _lint_add(
            findings,
            "error",
            "approvals.default_ttl_seconds",
            "approval TTL is not positive",
            "Use a positive TTL so approvals expire.",
        )
    elif config.approvals.default_ttl_seconds > 86_400:
        _lint_add(
            findings,
            "warning",
            "approvals.default_ttl_seconds",
            "approval TTL is longer than one day",
            "Use a shorter TTL for sensitive actions.",
        )
    if config.audit.destination == "stdout" and (
        config.runtime.mode == "stdio" or any(server.transport == "stdio" for server in config.servers)
    ):
        _lint_add(
            findings,
            "error",
            "audit.destination",
            "stdio mode cannot write audit logs to stdout",
            "Use audit.destination: file so stdout remains MCP protocol-only.",
        )


def _policy_match_is_empty(policy: PolicyConfig) -> bool:
    match = policy.match
    return not any(
        [
            match.server,
            match.method,
            match.capability_type,
            match.capability,
            match.capabilities,
            match.action,
            match.risk,
            match.access,
            match.resource_type,
            match.tag,
            match.tags,
            match.data_classification,
            match.environment,
            match.user,
            match.group,
            match.role,
            match.client_id,
            match.agent_id,
        ]
    )


def _lint_add(
    findings: list[dict[str, str]],
    severity: str,
    rule: str,
    message: str,
    recommendation: str,
) -> None:
    findings.append(
        {
            "severity": severity,
            "rule": rule,
            "message": message,
            "recommendation": recommendation,
        }
    )


def _print_lint_table(findings: list[dict[str, str]]) -> None:
    if not findings:
        console.print("[green]No lint findings[/green]")
        return
    table = Table("Severity", "Rule", "Message", "Recommendation")
    for finding in findings:
        style = {"error": "red", "warning": "yellow", "info": "blue"}.get(
            finding["severity"], "white"
        )
        table.add_row(
            f"[{style}]{finding['severity']}[/{style}]",
            finding["rule"],
            finding["message"],
            finding["recommendation"],
        )
    console.print(table)


def _print_audit_search_table(events: list[dict[str, object]]) -> None:
    if not events:
        console.print("[yellow]No matching audit events[/yellow]")
        return
    table = Table(expand=False)
    table.add_column("Timestamp", overflow="fold")
    table.add_column("Type", no_wrap=True)
    table.add_column("Server", no_wrap=True)
    table.add_column("Decision", no_wrap=True)
    table.add_column("Policy", overflow="fold")
    table.add_column("Correlation", overflow="fold")
    table.add_column("Approval", overflow="fold")
    for event in events:
        approval = event.get("approval")
        approval_id = approval.get("id") if isinstance(approval, dict) else ""
        table.add_row(
            str(event.get("timestamp") or ""),
            str(event.get("event_type") or ""),
            str(event.get("server") or ""),
            str(event.get("decision") or ""),
            str(event.get("policy_id") or ""),
            str(event.get("correlation_id") or ""),
            str(approval_id or ""),
        )
    Console(width=180).print(table)


def _print_policy_coverage_table(items: list[dict[str, object]]) -> None:
    if not items:
        console.print("[yellow]No mapped or discovered capabilities to analyze[/yellow]")
        return
    table = Table(expand=False)
    table.add_column("Server", no_wrap=True)
    table.add_column("Type", no_wrap=True)
    table.add_column("Capability", overflow="fold")
    table.add_column("Mapped", no_wrap=True)
    table.add_column("Decision", no_wrap=True)
    table.add_column("Policy", overflow="fold")
    table.add_column("Risk", no_wrap=True)
    table.add_column("Access", no_wrap=True)
    for item in items:
        table.add_row(
            str(item["server"]),
            str(item["capability_type"]),
            str(item["capability"]),
            "yes" if item["mapped"] else "no",
            str(item["decision"]),
            str(item.get("policy_id") or ""),
            str(item.get("risk") or ""),
            str(item.get("access") or ""),
        )
    Console(width=180).print(table)


def _print_policy_risks_table(findings: list[dict[str, object]]) -> None:
    if not findings:
        console.print("[green]No policy risk findings[/green]")
        return
    table = Table("Severity", "Rule", "Server", "Capability", "Policy", "Message")
    for finding in findings:
        style = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue"}.get(
            str(finding["severity"]), "white"
        )
        table.add_row(
            f"[{style}]{finding['severity']}[/{style}]",
            str(finding["rule_id"]),
            str(finding["server"]),
            str(finding.get("capability") or ""),
            str(finding.get("policy_id") or ""),
            str(finding["message"]),
        )
    Console(width=180).print(table)


def _print_unused_policies_table(policies: list[dict[str, object]]) -> None:
    if not policies:
        console.print("[green]No unused policies detected[/green]")
        return
    table = Table("Policy", "Effect", "Message")
    for policy in policies:
        table.add_row(
            str(policy["policy_id"]),
            str(policy["effect"]),
            str(policy["message"]),
        )
    console.print(table)


def _parse_cli_timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _policy_context(
    *,
    config_path: Path,
    server: str,
    method: str,
    capability: str | None,
    capability_type: str,
    arguments: str,
    subject: str,
    client_id: str | None,
    agent_id: str | None,
) -> tuple[MCPZTConfig, RequestContext]:
    config = load_config(config_path)
    parsed_arguments = json.loads(arguments)
    return config, RequestContext(
        server=server,
        method=method,
        capability_type=capability_type,  # type: ignore[arg-type]
        capability=capability,
        arguments=parsed_arguments,
        environment=config.project.environment,
        identity=Identity(
            subject=subject,
            client_id=client_id,
            agent_id=agent_id,
            auth_method=config.auth.mode,
            environment=config.project.environment,
        ),
        config_base_dir=config.config_base_dir,
    )


def _render_client_config(
    config: MCPZTConfig,
    kind: str,
    *,
    base_url: str,
    server_name: str | None,
) -> str:
    selected = [
        server
        for server in config.servers
        if server.transport == "http" and (server_name is None or server.name == server_name)
    ]
    if not selected:
        raise ValueError("no matching HTTP server configured")

    base = base_url.rstrip("/")
    servers = {
        f"mcpzt-{server.name}": {
            "command": "npx",
            "args": ["-y", "mcp-remote", f"{base}/mcp/{server.name}"],
        }
        for server in selected
    }

    if kind in {"claude-desktop", "cursor", "vscode", "json"}:
        return json.dumps({"mcpServers": servers}, indent=2, sort_keys=True)
    if kind == "claude-code":
        return "\n".join(
            f"claude mcp add mcpzt-{server.name} --transport http {base}/mcp/{server.name}"
            for server in selected
        )
    raise ValueError("kind must be claude-desktop, cursor, vscode, claude-code, or json")


def _default_claude_desktop_config() -> Path:
    return Path.home() / "Library/Application Support/Claude/claude_desktop_config.json"


def _print_imported_servers(servers: object) -> None:
    if not isinstance(servers, tuple):
        return
    table = Table("Client name", "MCPZT server", "Transport", "Env keys")
    for server in servers:
        table.add_row(
            server.source_name,
            server.logical_name,
            server.transport,
            ", ".join(server.env_keys) if server.env_keys else "",
        )
    console.print(table)


def _set_approval_status(
    path: Path,
    approval_id: str,
    status: str,
    *,
    decided_by: str | None = None,
    comment: str | None = None,
) -> None:
    config = load_config(path)
    store = ApprovalStore(config.approvals)
    try:
        approval = store.set_status(
            approval_id,
            status,  # type: ignore[arg-type]
            decided_by=decided_by or _default_approver(),
            decision_comment=comment,
        )
    except KeyError as exc:
        console.print(f"[red]Approval not found:[/red] {approval_id}")
        raise typer.Exit(1) from exc
    AuditLogger(config.audit).log_approval(status, approval.model_dump(mode="json"))
    ApprovalNotifier(config.approvals).notify(status, approval.model_dump(mode="json"))
    console.print(f"[green]{approval.id}[/green] -> {approval.status}")


def _emit_onboard_config(
    config_yaml: str,
    *,
    snapshots: list[CapabilitySnapshot],
    output: Path,
    force: bool,
    dry_run: bool,
    write_snapshots: bool,
    snapshot_dir: Path,
) -> None:
    if dry_run:
        console.print(config_yaml.rstrip())
        return
    if output.exists() and not force:
        raise typer.BadParameter(f"{output} already exists; pass --force to overwrite")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(config_yaml, encoding="utf-8")
    _write_onboard_snapshots(snapshots, write_snapshots=write_snapshots, snapshot_dir=snapshot_dir)
    console.print(f"[green]Wrote onboarded config[/green] {output}")
    if write_snapshots:
        console.print(f"[green]Wrote discovery snapshots[/green] {snapshot_dir}")


def _write_onboard_snapshots(
    snapshots: list[CapabilitySnapshot],
    *,
    write_snapshots: bool,
    snapshot_dir: Path,
) -> None:
    if not write_snapshots:
        return
    for snapshot in snapshots:
        write_snapshot(snapshot, snapshot_dir / f"{snapshot.server}.json")


def _emit_onboard_report(report: dict[str, object], report_json: str, output_format: str) -> None:
    if output_format == "json":
        console.print_json(report_json)
        return
    if output_format != "table":
        console.print(TABLE_JSON_FORMAT_ERROR)
        raise typer.Exit(1)
    _print_onboard_report(report)


def _onboard_base_config(server_specs: list[str], path: Path | None) -> MCPZTConfig:
    if server_specs:
        servers = parse_server_specs(server_specs)
        return MCPZTConfig.model_validate(
            {
                "project": {"name": "mcpzt-onboarded", "environment": "development"},
                "runtime": {"mode": "gateway", "default_decision": "deny"},
                "auth": {"mode": "none"},
                "servers": [server.model_dump(mode="json") for server in servers],
                "policies": [],
                "audit": {"destination": "file", "path": "./mcpzt-audit.jsonl"},
                "approvals": {"path": "./mcpzt-approvals.sqlite3", "backend": "sqlite"},
            }
        )
    if path is None:
        raise ValueError("pass --server name=url or --config with configured servers")
    return load_config(path)


def _discover_configured_servers(config: MCPZTConfig) -> list[CapabilitySnapshot]:
    snapshots: list[CapabilitySnapshot] = []
    for selected in config.servers:
        upstream = _upstream_for(selected)
        try:
            snapshots.append(discover_capabilities(config, selected.name, upstream))
        finally:
            if hasattr(upstream, "close"):
                upstream.close()  # type: ignore[attr-defined]
    return snapshots


def _print_onboard_report(report: dict[str, object]) -> None:
    _print_onboard_servers(report.get("servers"))
    _print_onboard_list(report.get("generated_policies"), "Generated policies")
    _print_onboard_list(report.get("recommendations"), "Recommendations")


def _print_onboard_servers(servers: object) -> None:
    if not isinstance(servers, list):
        return
    table = Table("Server", "Tools", "Resources", "Prompts", "Errors")
    for server in servers:
        if isinstance(server, dict):
            table.add_row(
                str(server.get("server") or ""),
                str(server.get("tools") or 0),
                str(server.get("resources") or 0),
                str(server.get("prompts") or 0),
                _onboard_error_summary(server.get("errors")),
            )
    console.print(table)


def _print_onboard_list(items: object, title: str) -> None:
    if not isinstance(items, list) or not items:
        return
    console.print(f"[bold]{title}[/bold]")
    for item in items:
        console.print(f"- {item}")


def _onboard_error_summary(errors: object) -> str:
    if not isinstance(errors, dict):
        return ""
    return ", ".join(sorted(str(key) for key in errors))


def _default_approver() -> str:
    return os.environ.get("MCPZT_APPROVER") or os.environ.get("USER") or "local-operator"


def _server(config: MCPZTConfig, name: str) -> ServerConfig:
    for server in config.servers:
        if server.name == name:
            return server
    raise typer.BadParameter(f"unknown server: {name}")


def _upstream_for(server: ServerConfig) -> UpstreamClient:
    if server.transport == "http":
        return HTTPUpstreamClient()
    return StdioProcessUpstream(server)


def _doctor_config(checks: list[tuple[str, str, str]], config: MCPZTConfig) -> None:
    _doctor_runtime(checks, config)
    _doctor_auth(checks, config)
    for server in config.servers:
        _doctor_server(checks, server)
    _doctor_state_paths(checks, config)


def _doctor_runtime(checks: list[tuple[str, str, str]], config: MCPZTConfig) -> None:
    if config.runtime.default_decision == "deny":
        _doctor_add(checks, "OK", "runtime", "default_decision is deny")
    else:
        _doctor_add(checks, "WARN", "runtime", "default_decision is allow")

    if config.project.environment == "production" and config.runtime.dry_run:
        _doctor_add(checks, "FAIL", "runtime", "production dry_run is enabled")

    if config.project.environment == "production" and config.auth.trust_identity_headers:
        _doctor_add(
            checks,
            "WARN",
            "auth",
            "production trusts x-mcpzt identity headers; ensure a trusted gateway strips spoofed headers",
        )

    if config.project.environment == "production" and not config.runtime.allowed_origins:
        _doctor_add(
            checks,
            "WARN",
            "origin",
            "production config has no runtime.allowed_origins",
        )
    elif config.runtime.allowed_origins:
        _doctor_add(
            checks,
            "OK",
            "origin",
            f"{len(config.runtime.allowed_origins)} allowed origin(s)",
        )


def _doctor_auth(checks: list[tuple[str, str, str]], config: MCPZTConfig) -> None:
    if config.auth.mode == "none":
        _doctor_add(checks, "WARN", "auth", "auth.mode is none")
    elif config.auth.mode in {"static_token", "api_key"}:
        _doctor_static_or_api_key_auth(checks, config)
    elif config.auth.mode == "jwt":
        _doctor_jwt_auth(checks, config)
    elif config.auth.mode == "oidc":
        _doctor_oidc_auth(checks, config)


def _doctor_static_or_api_key_auth(
    checks: list[tuple[str, str, str]], config: MCPZTConfig
) -> None:
    missing_auth_refs = _doctor_secret_refs(checks, "auth", _auth_secret_refs(config))
    secret_source_issues = _doctor_secret_sources(checks, "auth", _auth_secret_sources(config))
    if not _auth_has_token(config):
        _doctor_add(checks, "FAIL", "auth", f"{config.auth.mode} requires auth.token")
        return
    if _auth_inline_token(config) in {"change-me", "changeme", "secret"}:
        _doctor_add(checks, "FAIL", "auth", "replace placeholder auth.token")
        return
    detail = _auth_detail(checks, config)
    if not missing_auth_refs and not secret_source_issues:
        _doctor_add(checks, "OK", "auth", detail)


def _doctor_jwt_auth(checks: list[tuple[str, str, str]], config: MCPZTConfig) -> None:
    missing_auth_refs = _doctor_secret_refs(checks, "auth", _auth_secret_refs(config))
    secret_source_issues = _doctor_secret_sources(checks, "auth", _auth_secret_sources(config))
    if not _auth_has_token(config) and not config.auth.jwks_url:
        _doctor_add(checks, "FAIL", "auth", "jwt requires auth.token or auth.jwks_url")
    elif not missing_auth_refs and not secret_source_issues:
        _doctor_add(checks, "OK", "auth", "jwt validation configured")


def _doctor_oidc_auth(checks: list[tuple[str, str, str]], config: MCPZTConfig) -> None:
    if not config.auth.issuer and not config.auth.jwks_url:
        _doctor_add(checks, "FAIL", "auth", "oidc requires auth.issuer or auth.jwks_url")
    else:
        _doctor_add(checks, "OK", "auth", "oidc validation configured")


def _auth_detail(checks: list[tuple[str, str, str]], config: MCPZTConfig) -> str:
    detail = f"{config.auth.mode} configured"
    if config.auth.token_env:
        return detail + " from environment"
    if _auth_secret_sources(config):
        return detail + " from secret reference"
    if config.auth.token:
        _doctor_add(checks, "WARN", "auth", "inline auth.token should not be committed")
        return detail + "; prefer auth.token_env for real secrets"
    return detail


def _doctor_state_paths(checks: list[tuple[str, str, str]], config: MCPZTConfig) -> None:
    if config.audit.destination == "stdout":
        if config.runtime.mode == "stdio" or any(server.transport == "stdio" for server in config.servers):
            _doctor_add(checks, "FAIL", "audit", "stdio mode cannot use audit.destination stdout")
        else:
            _doctor_add(checks, "OK", "audit", "audit writes to stdout")
    else:
        _doctor_parent_path(checks, "audit", Path(config.audit.path), "audit path parent")

    _doctor_parent_path(checks, "approvals", Path(config.approvals.path), "approval store parent")


def _doctor_parent_path(
    checks: list[tuple[str, str, str]], check: str, path: Path, label: str
) -> None:
    parent = path.parent
    if parent.exists():
        _doctor_add(checks, "OK", check, f"{label} exists: {parent}")
    else:
        _doctor_add(checks, "WARN", check, f"{label} will be created: {parent}")


def _doctor_server(checks: list[tuple[str, str, str]], server: ServerConfig) -> None:
    if server.transport == "http":
        parsed = urlparse(server.upstream or "")
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            _doctor_add(checks, "FAIL", f"server:{server.name}", "invalid HTTP upstream URL")
        else:
            _doctor_add(checks, "OK", f"server:{server.name}", f"http upstream {server.upstream}")
        _doctor_upstream_headers(checks, server)
        return

    executable = server.command[0] if server.command else ""
    exists = Path(executable).exists() if "/" in executable else shutil.which(executable) is not None
    if exists:
        _doctor_add(checks, "OK", f"server:{server.name}", f"stdio command {executable}")
    else:
        _doctor_add(checks, "FAIL", f"server:{server.name}", f"command not found: {executable}")


def _doctor_add(
    checks: list[tuple[str, str, str]],
    status: str,
    check: str,
    details: str,
) -> None:
    checks.append((status, check, details))


def _auth_has_token(config: MCPZTConfig) -> bool:
    return bool(config.auth.token or config.auth.token_env)


def _auth_inline_token(config: MCPZTConfig) -> str | None:
    if config.auth.token and not referenced_secret_sources(config.auth.token):
        return config.auth.token
    return None


def _auth_secret_refs(config: MCPZTConfig) -> list[str]:
    refs = []
    if config.auth.token_env:
        refs.append(config.auth.token_env)
    refs.extend(referenced_env_vars(config.auth.token))
    return refs


def _auth_secret_sources(config: MCPZTConfig) -> list[tuple[str, str]]:
    return [source for source in referenced_secret_sources(config.auth.token) if source[0] != "env"]


def _doctor_secret_refs(
    checks: list[tuple[str, str, str]],
    check: str,
    refs: list[str],
) -> bool:
    missing = [name for name in refs if not os.environ.get(name)]
    if missing:
        _doctor_add(
            checks,
            "FAIL",
            check,
            f"unset environment variable(s): {', '.join(sorted(set(missing)))}",
        )
        return True
    return False


def _doctor_secret_sources(
    checks: list[tuple[str, str, str]],
    check: str,
    sources: list[tuple[str, str]],
) -> bool:
    failures: list[str] = []
    for kind, reference in sources:
        if kind == "env" and not os.environ.get(reference):
            failures.append(f"unset env:{reference}")
        elif kind == "file":
            path_text = urlparse(reference).path if reference.startswith("file://") else reference[5:]
            if not Path(path_text).expanduser().exists():
                failures.append(f"missing file secret:{path_text}")
        elif not secret_provider_available(kind):
            failures.append(f"{kind} CLI not found")
    if failures:
        _doctor_add(checks, "FAIL", check, "; ".join(failures))
        return True
    return False


def _doctor_upstream_headers(
    checks: list[tuple[str, str, str]],
    server: ServerConfig,
) -> None:
    if not server.upstream_headers:
        return
    sources: list[tuple[str, str]] = []
    inline_sensitive = []
    for key, value in server.upstream_headers.items():
        value_sources = referenced_secret_sources(value)
        sources.extend(value_sources)
        if not value_sources and _looks_sensitive_header(key):
            inline_sensitive.append(key)
    missing_refs = _doctor_secret_sources(checks, f"server:{server.name}", sources)
    if inline_sensitive:
        _doctor_add(
            checks,
            "WARN",
            f"server:{server.name}",
            f"inline sensitive upstream header(s): {', '.join(sorted(inline_sensitive))}",
        )
    elif not missing_refs:
        _doctor_add(
            checks,
            "OK",
            f"server:{server.name}",
            f"{len(server.upstream_headers)} configured upstream header(s)",
        )


def _looks_sensitive_header(header: str) -> bool:
    normalized = header.lower()
    return any(word in normalized for word in ["authorization", "api-key", "apikey", "token", "secret"])
