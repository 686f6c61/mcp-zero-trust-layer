from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Annotated
from urllib.parse import urlparse

import typer
from rich.console import Console
from rich.table import Table

from mcp_zero_trust_layer import __version__
from mcp_zero_trust_layer.approvals import ApprovalNotifier, ApprovalStore
from mcp_zero_trust_layer.audit import AuditLogger, verify_audit_hash_chain
from mcp_zero_trust_layer.capabilities.discovery import (
    default_snapshot_path,
    diff_snapshots,
    discover_capabilities,
    read_snapshot,
    write_snapshot,
)
from mcp_zero_trust_layer.config import load_config
from mcp_zero_trust_layer.config.models import MCPZTConfig, ServerConfig
from mcp_zero_trust_layer.config.secrets import (
    referenced_env_vars,
    referenced_secret_sources,
    secret_provider_available,
)
from mcp_zero_trust_layer.core import RequestContext
from mcp_zero_trust_layer.errors import ConfigError
from mcp_zero_trust_layer.identity import Identity
from mcp_zero_trust_layer.packs import add_pack, list_packs, read_pack
from mcp_zero_trust_layer.policy import PolicyEngine
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
DEFAULT_CONFIG_PATH = Path("mcpzt.yaml")


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
  path: ./mcpzt-approvals.json
  default_ttl_seconds: 900
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


@approve_app.command("list")
def approve_list(
    path: Annotated[Path, typer.Option("--config", "-c")] = DEFAULT_CONFIG_PATH,
) -> None:
    """List pending approvals."""
    config = load_config(path)
    approvals = ApprovalStore(config.approvals).list()
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
            help="claude-desktop, cursor, vscode, claude-code, or json.",
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


@app.command()
def doctor(
    path: Annotated[Path | None, typer.Option("--config", "-c")] = None,
) -> None:
    """Diagnose local environment and optional MCPZT config."""
    checks: list[tuple[str, str, str]] = []
    _doctor_add(checks, "OK", "package", f"mcp-zero-trust-layer {__version__} importable")
    config: MCPZTConfig | None = None

    if path is None:
        _doctor_add(checks, "WARN", "config", "pass --config to validate a project config")
    else:
        try:
            config = load_config(path)
        except ConfigError as exc:
            _doctor_add(checks, "FAIL", "config", str(exc))
        else:
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

    if any(status == "FAIL" for status, _, _ in checks):
        raise typer.Exit(1)


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
