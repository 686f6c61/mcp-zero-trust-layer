from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from mcp_zero_trust_layer.capabilities.discovery import CapabilitySnapshot
from mcp_zero_trust_layer.cli import main as cli_main
from mcp_zero_trust_layer.cli.main import app

runner = CliRunner()


def dev_config(*, audit: str = "./audit.jsonl", approvals: str = "./approvals.json") -> str:
    return f"""
project:
  name: cov-test
  environment: development
runtime:
  default_decision: deny
auth:
  mode: none
servers:
  - name: github
    transport: http
    upstream: http://localhost:3001/mcp
policies: []
audit:
  destination: file
  path: {audit}
approvals:
  path: {approvals}
"""


def write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def snapshot(server: str, tools: list[dict[str, str]] | None = None) -> CapabilitySnapshot:
    return CapabilitySnapshot(
        server=server,
        discovered_at="2026-06-14T10:00:00Z",
        tools=tools if tools is not None else [{"name": f"{server}.tool", "description": "d"}],
        resources=[],
        prompts=[],
    )


# --------------------------------------------------------------------------- #
# version / init / demo
# --------------------------------------------------------------------------- #


def test_version_prints_version() -> None:
    from mcp_zero_trust_layer import __version__

    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_init_creates_and_requires_force(tmp_path: Path) -> None:
    config = tmp_path / "mcpzt.yaml"

    created = runner.invoke(app, ["init", "--config", str(config)])
    assert created.exit_code == 0
    assert config.exists()

    conflict = runner.invoke(app, ["init", "--config", str(config)])
    assert conflict.exit_code == 2

    forced = runner.invoke(app, ["init", "--config", str(config), "--force"])
    assert forced.exit_code == 0


def test_demo_requires_force_when_files_exist(tmp_path: Path) -> None:
    output = tmp_path / "demo"

    first = runner.invoke(app, ["demo", "--output", str(output)])
    assert first.exit_code == 0

    conflict = runner.invoke(app, ["demo", "--output", str(output)])
    assert conflict.exit_code == 2

    forced = runner.invoke(app, ["demo", "--output", str(output), "--force"])
    assert forced.exit_code == 0


# --------------------------------------------------------------------------- #
# onboard
# --------------------------------------------------------------------------- #


def test_onboard_without_inputs_reports_error() -> None:
    result = runner.invoke(app, ["onboard"])

    assert result.exit_code == 1
    assert "Cannot onboard" in result.stdout


# --------------------------------------------------------------------------- #
# config validate / lint
# --------------------------------------------------------------------------- #


def test_config_validate_success(tmp_path: Path) -> None:
    config = write(tmp_path, "mcpzt.yaml", dev_config())

    result = runner.invoke(app, ["config", "validate", "--config", str(config)])

    assert result.exit_code == 0
    assert "Config valid" in result.stdout


def test_config_validate_failure(tmp_path: Path) -> None:
    config = write(tmp_path, "mcpzt.yaml", "project: {name: x}\n:not-valid")

    result = runner.invoke(app, ["config", "validate", "--config", str(config)])

    assert result.exit_code == 1
    assert "Invalid config" in result.stdout


def test_config_lint_error_for_invalid_config(tmp_path: Path) -> None:
    config = write(tmp_path, "mcpzt.yaml", ":not valid yaml:")

    result = runner.invoke(app, ["config", "lint", "--config", str(config)])

    assert result.exit_code == 1
    assert "Cannot lint config" in result.stdout


def test_config_lint_table_with_warnings(tmp_path: Path) -> None:
    config = write(tmp_path, "mcpzt.yaml", dev_config())

    result = runner.invoke(app, ["config", "lint", "--config", str(config)])

    assert result.exit_code == 0
    assert "auth.mode" in result.stdout


def test_config_lint_table_without_findings(tmp_path: Path) -> None:
    secret = write(tmp_path, "token.txt", "s3cret")
    config = write(
        tmp_path,
        "mcpzt.yaml",
        f"""
project:
  name: clean
  environment: development
runtime:
  default_decision: deny
auth:
  mode: static_token
  token_env: MCPZT_CLEAN_TOKEN
servers:
  - name: github
    transport: http
    upstream: http://localhost:3001/mcp
policies: []
audit:
  destination: file
  path: {tmp_path / "audit.jsonl"}
approvals:
  path: {tmp_path / "approvals.json"}
  default_ttl_seconds: 900
""",
    )
    assert secret.exists()

    result = runner.invoke(app, ["config", "lint", "--config", str(config)])

    assert result.exit_code == 0
    assert "No lint findings" in result.stdout


def test_config_lint_covers_production_rules(tmp_path: Path) -> None:
    config = write(
        tmp_path,
        "mcpzt.yaml",
        f"""
project:
  name: prod
  environment: production
runtime:
  default_decision: deny
  dry_run: true
  allow_dry_run_in_production: true
  allow_auth_none_in_production: true
  public_base_url: https://mcpzt.example
auth:
  mode: none
  trust_identity_headers: true
servers:
  - name: github
    transport: http
    upstream: http://public.example.com/mcp
    upstream_headers:
      Authorization: Bearer inline-secret
policies:
  - id: allow-critical
    effect: allow
    match:
      risk: critical
audit:
  destination: file
  path: {tmp_path / "audit.jsonl"}
approvals:
  path: {tmp_path / "approvals.json"}
""",
    )

    result = runner.invoke(
        app, ["config", "lint", "--format", "json", "--config", str(config)]
    )

    assert result.exit_code == 1
    rules = {finding["rule"] for finding in json.loads(result.stdout)}
    assert "runtime.dry_run" in rules
    assert "runtime.allow_dry_run_in_production" in rules
    assert "runtime.allow_auth_none_in_production" in rules
    assert "runtime.allowed_origins" in rules
    assert "auth.trust_identity_headers" in rules
    assert any(rule.startswith("servers.github.upstream_headers.") for rule in rules)
    assert "servers.github.upstream" in rules
    assert "policies.allow-critical" in rules


def test_config_lint_covers_development_rules(tmp_path: Path) -> None:
    config = write(
        tmp_path,
        "mcpzt.yaml",
        f"""
project:
  name: dev
  environment: development
runtime:
  default_decision: deny
auth:
  mode: none
servers:
  - name: github
    transport: http
    upstream: http://localhost:3001/mcp
capability_mappings:
  github:
    tools:
      github.empty: {{}}
policies:
  - id: semantic-allow
    effect: allow
    match:
      action: code.read
audit:
  destination: file
  path: {tmp_path / "audit.jsonl"}
approvals:
  backend: sqlite
  path: {tmp_path / "approvals.json"}
  default_ttl_seconds: 200000
""",
    )

    result = runner.invoke(
        app, ["config", "lint", "--format", "json", "--config", str(config)]
    )

    rules = {finding["rule"] for finding in json.loads(result.stdout)}
    assert "policies.semantic-allow" in rules
    assert "capability_mappings.github.tools.github.empty" in rules
    assert "approvals.path" in rules
    assert "approvals.default_ttl_seconds" in rules


def test_config_lint_inline_placeholder_token_and_ttl_error(tmp_path: Path) -> None:
    config = write(
        tmp_path,
        "mcpzt.yaml",
        f"""
project:
  name: dev
  environment: development
runtime:
  default_decision: deny
auth:
  mode: static_token
  token: change-me
servers:
  - name: local
    transport: stdio
    command: [echo, hi]
policies: []
audit:
  destination: stdout
approvals:
  path: {tmp_path / "approvals.json"}
  default_ttl_seconds: 0
""",
    )

    result = runner.invoke(
        app, ["config", "lint", "--format", "json", "--config", str(config)]
    )

    assert result.exit_code == 1
    rules = {finding["rule"] for finding in json.loads(result.stdout)}
    assert "auth.token" in rules
    assert "approvals.default_ttl_seconds" in rules
    assert "audit.destination" in rules


def test_config_lint_jwt_without_required_scopes(tmp_path: Path) -> None:
    config = write(
        tmp_path,
        "mcpzt.yaml",
        f"""
project:
  name: prod
  environment: production
runtime:
  default_decision: deny
  allowed_origins: [https://ok.example]
  public_base_url: https://mcpzt.example
auth:
  mode: jwt
  issuer: https://issuer.example
  audience: mcpzt
  jwks_url: https://issuer.example/jwks
servers:
  - name: github
    transport: http
    upstream: https://github.example/mcp
policies: []
audit:
  destination: file
  path: {tmp_path / "audit.jsonl"}
approvals:
  path: {tmp_path / "approvals.json"}
""",
    )

    result = runner.invoke(
        app, ["config", "lint", "--format", "json", "--config", str(config)]
    )

    rules = {finding["rule"] for finding in json.loads(result.stdout)}
    assert "auth.required_scopes" in rules


# --------------------------------------------------------------------------- #
# policy test / explain
# --------------------------------------------------------------------------- #


def test_policy_test_success(tmp_path: Path) -> None:
    config = write(tmp_path, "mcpzt.yaml", dev_config())

    result = runner.invoke(
        app,
        [
            "policy",
            "test",
            "--config",
            str(config),
            "--server",
            "github",
            "--method",
            "tools/call",
            "--capability",
            "github.search_issues",
        ],
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)["decision"] == "deny"


def test_policy_test_invalid_arguments(tmp_path: Path) -> None:
    config = write(tmp_path, "mcpzt.yaml", dev_config())

    result = runner.invoke(
        app,
        [
            "policy",
            "test",
            "--config",
            str(config),
            "--server",
            "github",
            "--method",
            "tools/call",
            "--arguments",
            "{not-json",
        ],
    )

    assert result.exit_code == 1
    assert "Cannot run policy test" in result.stdout


def test_policy_explain_invalid_config(tmp_path: Path) -> None:
    config = write(tmp_path, "mcpzt.yaml", ":not valid:")

    result = runner.invoke(
        app,
        [
            "policy",
            "explain",
            "--config",
            str(config),
            "--server",
            "github",
            "--method",
            "tools/call",
        ],
    )

    assert result.exit_code == 1
    assert "Cannot explain policy" in result.stdout


# --------------------------------------------------------------------------- #
# policy coverage / risks / unused
# --------------------------------------------------------------------------- #


RISK_CONFIG = """
project:
  name: risk
  environment: development
runtime:
  default_decision: deny
auth:
  mode: none
servers:
  - name: github
    transport: http
    upstream: http://localhost:3001/mcp
capability_mappings:
  github:
    tools:
      github.delete_repo:
        action: code.delete
        risk: critical
        access: delete
      github.search:
        action: code.read
        risk: low
        access: read
policies:
  - id: allow-delete
    effect: allow
    match:
      server: github
      capability: github.delete_repo
  - id: unused-policy
    effect: allow
    match:
      server: other
      capability: nope.tool
audit:
  destination: file
  path: ./a.jsonl
"""


def test_policy_coverage_table_and_invalid_format(tmp_path: Path) -> None:
    config = write(tmp_path, "mcpzt.yaml", RISK_CONFIG)

    table = runner.invoke(app, ["policy", "coverage", "--config", str(config)])
    assert table.exit_code == 0
    assert "github.delete_repo" in table.stdout

    invalid = runner.invoke(
        app, ["policy", "coverage", "--config", str(config), "--format", "xml"]
    )
    assert invalid.exit_code == 1


def test_policy_coverage_error(tmp_path: Path) -> None:
    config = write(tmp_path, "mcpzt.yaml", ":bad:")

    result = runner.invoke(app, ["policy", "coverage", "--config", str(config)])

    assert result.exit_code == 1
    assert "Cannot build policy coverage" in result.stdout


def test_policy_coverage_empty_table(tmp_path: Path) -> None:
    config = write(tmp_path, "mcpzt.yaml", dev_config())

    result = runner.invoke(app, ["policy", "coverage", "--config", str(config)])

    assert result.exit_code == 0
    assert "No mapped or discovered capabilities" in result.stdout


def test_policy_risks_table_json_and_invalid(tmp_path: Path) -> None:
    config = write(tmp_path, "mcpzt.yaml", RISK_CONFIG)

    table = runner.invoke(app, ["policy", "risks", "--config", str(config)])
    assert table.exit_code == 2

    as_json = runner.invoke(
        app, ["policy", "risks", "--config", str(config), "--format", "json"]
    )
    assert as_json.exit_code == 0
    assert "findings" in as_json.stdout

    invalid = runner.invoke(
        app, ["policy", "risks", "--config", str(config), "--format", "xml"]
    )
    assert invalid.exit_code == 1


def test_policy_risks_error(tmp_path: Path) -> None:
    config = write(tmp_path, "mcpzt.yaml", ":bad:")

    result = runner.invoke(app, ["policy", "risks", "--config", str(config)])

    assert result.exit_code == 1
    assert "Cannot analyze policy risks" in result.stdout


def test_policy_risks_empty(tmp_path: Path) -> None:
    config = write(tmp_path, "mcpzt.yaml", dev_config())

    result = runner.invoke(app, ["policy", "risks", "--config", str(config)])

    assert result.exit_code == 0
    assert "No policy risk findings" in result.stdout


def test_policy_unused_table_json_and_invalid(tmp_path: Path) -> None:
    config = write(tmp_path, "mcpzt.yaml", RISK_CONFIG)

    table = runner.invoke(app, ["policy", "unused", "--config", str(config)])
    assert table.exit_code == 0
    assert "unused-policy" in table.stdout

    as_json = runner.invoke(
        app, ["policy", "unused", "--config", str(config), "--format", "json"]
    )
    assert as_json.exit_code == 0
    assert "policies" in as_json.stdout

    invalid = runner.invoke(
        app, ["policy", "unused", "--config", str(config), "--format", "xml"]
    )
    assert invalid.exit_code == 1


def test_policy_unused_error(tmp_path: Path) -> None:
    config = write(tmp_path, "mcpzt.yaml", ":bad:")

    result = runner.invoke(app, ["policy", "unused", "--config", str(config)])

    assert result.exit_code == 1
    assert "Cannot analyze unused policies" in result.stdout


def test_policy_unused_empty(tmp_path: Path) -> None:
    config = write(tmp_path, "mcpzt.yaml", dev_config())

    result = runner.invoke(app, ["policy", "unused", "--config", str(config)])

    assert result.exit_code == 0
    assert "No unused policies detected" in result.stdout


# --------------------------------------------------------------------------- #
# run / wrap
# --------------------------------------------------------------------------- #


def test_run_success(tmp_path: Path, monkeypatch) -> None:
    config = write(tmp_path, "mcpzt.yaml", dev_config())
    calls: dict[str, object] = {}

    def fake_run_http_server(path, *, host, port, server):  # noqa: ANN001
        calls["path"] = path
        calls["host"] = host
        calls["port"] = port

    monkeypatch.setattr(cli_main, "run_http_server", fake_run_http_server)

    result = runner.invoke(
        app, ["run", "--config", str(config), "--host", "0.0.0.0", "--port", "9999"]
    )

    assert result.exit_code == 0
    assert calls["host"] == "0.0.0.0"
    assert calls["port"] == 9999


def test_run_without_http_servers(tmp_path: Path) -> None:
    config = write(
        tmp_path,
        "mcpzt.yaml",
        """
project:
  name: stdio-only
  environment: development
runtime:
  mode: stdio
  default_decision: deny
auth:
  mode: none
servers:
  - name: local
    transport: stdio
    command: [echo, hi]
policies: []
audit:
  destination: file
  path: ./a.jsonl
""",
    )

    result = runner.invoke(app, ["run", "--config", str(config)])

    assert result.exit_code == 1
    assert "No HTTP servers configured" in result.stdout


def test_wrap_success(tmp_path: Path, monkeypatch) -> None:
    config = write(
        tmp_path,
        "mcpzt.yaml",
        """
project:
  name: stdio
  environment: development
runtime:
  mode: stdio
  default_decision: deny
auth:
  mode: none
servers:
  - name: local
    transport: stdio
    command: [echo, hi]
policies: []
audit:
  destination: file
  path: ./a.jsonl
""",
    )
    monkeypatch.setattr(cli_main, "run_stdio_wrapper", lambda path, server_name=None: 0)

    result = runner.invoke(app, ["wrap", "--config", str(config), "--server", "local"])

    assert result.exit_code == 0


def test_wrap_without_matching_server(tmp_path: Path) -> None:
    config = write(tmp_path, "mcpzt.yaml", dev_config())

    result = runner.invoke(app, ["wrap", "--config", str(config)])

    assert result.exit_code == 1
    assert "No matching stdio server" in result.stdout


# --------------------------------------------------------------------------- #
# discover / diff / scan
# --------------------------------------------------------------------------- #


def test_discover_writes_snapshot(tmp_path: Path, monkeypatch) -> None:
    config = write(
        tmp_path,
        "mcpzt.yaml",
        """
project:
  name: disc
  environment: development
runtime:
  mode: stdio
  default_decision: deny
auth:
  mode: none
servers:
  - name: local
    transport: stdio
    command: [echo, hi]
policies: []
audit:
  destination: file
  path: ./a.jsonl
""",
    )
    output = tmp_path / "snap.json"
    monkeypatch.setattr(
        cli_main, "discover_capabilities", lambda c, s, u: snapshot(s)
    )

    result = runner.invoke(
        app,
        ["discover", "--config", str(config), "--server", "local", "--output", str(output)],
    )

    assert result.exit_code == 0
    assert output.exists()


STDIO_CONFIG = """
project:
  name: stdio
  environment: development
runtime:
  mode: stdio
  default_decision: deny
auth:
  mode: none
servers:
  - name: local
    transport: stdio
    command: [echo, hi]
policies: []
audit:
  destination: file
  path: ./a.jsonl
"""


def test_diff_reports_changes(tmp_path: Path, monkeypatch) -> None:
    config = write(tmp_path, "mcpzt.yaml", STDIO_CONFIG)
    previous = tmp_path / "prev.json"
    previous.write_text(snapshot("local", tools=[]).model_dump_json(), encoding="utf-8")

    monkeypatch.setattr(
        cli_main,
        "discover_capabilities",
        lambda c, s, u: snapshot(s, tools=[{"name": "local.new", "description": "d"}]),
    )

    result = runner.invoke(
        app,
        ["diff", "--config", str(config), "--server", "local", "--snapshot", str(previous)],
    )

    assert result.exit_code == 2


def test_scan_live_discovery(tmp_path: Path, monkeypatch) -> None:
    config = write(tmp_path, "mcpzt.yaml", STDIO_CONFIG)
    monkeypatch.setattr(
        cli_main, "discover_capabilities", lambda c, s, u: snapshot(s, tools=[])
    )

    result = runner.invoke(app, ["scan", "--config", str(config), "--server", "local"])

    assert result.exit_code in (0, 2)


def test_scan_without_server_or_snapshot(tmp_path: Path) -> None:
    config = write(tmp_path, "mcpzt.yaml", dev_config())

    result = runner.invoke(app, ["scan", "--config", str(config)])

    assert result.exit_code == 1
    assert "Cannot scan" in result.stdout


def test_discover_unknown_server(tmp_path: Path) -> None:
    config = write(tmp_path, "mcpzt.yaml", dev_config())

    result = runner.invoke(
        app, ["discover", "--config", str(config), "--server", "ghost"]
    )

    assert result.exit_code == 2


def test_onboard_from_config_with_stdio_server(tmp_path: Path, monkeypatch) -> None:
    config = write(tmp_path, "mcpzt.yaml", STDIO_CONFIG)
    monkeypatch.setattr(
        cli_main, "discover_capabilities", lambda c, s, u: snapshot(s, tools=[])
    )

    result = runner.invoke(
        app,
        [
            "onboard",
            "--config",
            str(config),
            "--output",
            str(tmp_path / "generated.yaml"),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert (tmp_path / "generated.yaml").exists()


# --------------------------------------------------------------------------- #
# audit tail / verify / search
# --------------------------------------------------------------------------- #


def test_audit_tail_requires_file_destination(tmp_path: Path) -> None:
    config = write(
        tmp_path,
        "mcpzt.yaml",
        """
project:
  name: a
  environment: development
runtime:
  default_decision: deny
auth:
  mode: none
servers:
  - name: github
    transport: http
    upstream: http://localhost:3001/mcp
policies: []
audit:
  destination: stdout
""",
    )

    result = runner.invoke(app, ["audit", "tail", "--config", str(config)])

    assert result.exit_code == 1
    assert "audit tail requires" in result.stdout


def test_audit_tail_no_file_yet(tmp_path: Path) -> None:
    audit = tmp_path / "missing-audit.jsonl"
    config = write(tmp_path, "mcpzt.yaml", dev_config(audit=str(audit)))

    result = runner.invoke(app, ["audit", "tail", "--config", str(config)])

    assert result.exit_code == 0
    assert "No audit file yet" in result.stdout


def test_audit_tail_prints_events(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    audit.write_text('{"event_type":"x"}\n{"event_type":"y"}\n', encoding="utf-8")
    config = write(tmp_path, "mcpzt.yaml", dev_config(audit=str(audit)))

    result = runner.invoke(app, ["audit", "tail", "--config", str(config), "--lines", "1"])

    assert result.exit_code == 0
    assert "event_type" in result.stdout


def test_audit_verify_requires_file_path(tmp_path: Path) -> None:
    config = write(
        tmp_path,
        "mcpzt.yaml",
        """
project:
  name: a
  environment: development
runtime:
  default_decision: deny
auth:
  mode: none
servers:
  - name: github
    transport: http
    upstream: http://localhost:3001/mcp
policies: []
audit:
  destination: stdout
""",
    )

    result = runner.invoke(app, ["audit", "verify", "--config", str(config)])

    assert result.exit_code == 1
    assert "audit verify requires" in result.stdout


def test_audit_verify_ok(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    audit.write_text("", encoding="utf-8")
    config = write(tmp_path, "mcpzt.yaml", dev_config(audit=str(audit)))

    result = runner.invoke(app, ["audit", "verify", "--config", str(config)])

    assert result.exit_code == 0
    assert "OK" in result.stdout


def test_audit_verify_fail(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    audit.write_text('{"event_type":"x"}\n', encoding="utf-8")
    config = write(tmp_path, "mcpzt.yaml", dev_config())

    result = runner.invoke(
        app, ["audit", "verify", "--config", str(config), "--audit-path", str(audit)]
    )

    assert result.exit_code == 1
    assert "FAIL" in result.stdout


def test_audit_search_requires_file_destination(tmp_path: Path) -> None:
    config = write(
        tmp_path,
        "mcpzt.yaml",
        """
project:
  name: a
  environment: development
runtime:
  default_decision: deny
auth:
  mode: none
servers:
  - name: github
    transport: http
    upstream: http://localhost:3001/mcp
policies: []
audit:
  destination: stdout
""",
    )

    result = runner.invoke(app, ["audit", "search", "--config", str(config)])

    assert result.exit_code == 1
    assert "audit search requires" in result.stdout


def test_audit_search_invalid_timestamp(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    audit.write_text('{"event_type":"x"}\n', encoding="utf-8")
    config = write(tmp_path, "mcpzt.yaml", dev_config(audit=str(audit)))

    result = runner.invoke(
        app, ["audit", "search", "--config", str(config), "--since", "not-a-date"]
    )

    assert result.exit_code == 1


def test_audit_search_table_with_events(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    audit.write_text(
        json.dumps(
            {
                "timestamp": "2026-06-14T10:00:00+00:00",
                "event_type": "policy_decision",
                "server": "github",
                "decision": "allow",
                "policy_id": "allow-search",
                "correlation_id": "corr-1",
                "approval": {"id": "appr_1"},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    config = write(tmp_path, "mcpzt.yaml", dev_config(audit=str(audit)))

    result = runner.invoke(
        app,
        ["audit", "search", "--config", str(config), "--since", "2026-01-01T00:00:00+00:00"],
    )

    assert result.exit_code == 0
    assert "policy_decision" in result.stdout


def test_audit_search_table_empty(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    audit.write_text("", encoding="utf-8")
    config = write(tmp_path, "mcpzt.yaml", dev_config(audit=str(audit)))

    result = runner.invoke(
        app, ["audit", "search", "--config", str(config), "--decision", "deny"]
    )

    assert result.exit_code == 0
    assert "No matching audit events" in result.stdout


# --------------------------------------------------------------------------- #
# approve show / allow / deny / serve
# --------------------------------------------------------------------------- #


def approvals_config(tmp_path: Path, approvals: Path) -> Path:
    return write(
        tmp_path,
        "mcpzt.yaml",
        dev_config(audit=str(tmp_path / "audit.jsonl"), approvals=str(approvals)),
    )


def pending_approval(approvals: Path, approval_id: str) -> None:
    approvals.write_text(
        json.dumps(
            {
                approval_id: {
                    "id": approval_id,
                    "status": "pending",
                    "server": "github",
                    "capability": "github.merge_pull_request",
                    "capability_type": "tool",
                    "policy_id": "critical-needs-approval",
                    "identity_subject": "ana@example.com",
                    "arguments_hash": "abc123",
                    "arguments_redacted": {"repo": "acme/api"},
                    "created_at": "2026-06-14T09:00:00+00:00",
                    "expires_at": "2126-06-14T09:15:00+00:00",
                }
            }
        ),
        encoding="utf-8",
    )


def test_approve_show_found_and_missing(tmp_path: Path) -> None:
    approvals = tmp_path / "approvals.json"
    approval_id = "appr_" + ("c" * 32)
    pending_approval(approvals, approval_id)
    config = approvals_config(tmp_path, approvals)

    found = runner.invoke(app, ["approve", "show", approval_id, "--config", str(config)])
    assert found.exit_code == 0
    assert approval_id in found.stdout

    missing = runner.invoke(app, ["approve", "show", "nope", "--config", str(config)])
    assert missing.exit_code == 1
    assert "Approval not found" in missing.stdout


def test_approve_allow_success(tmp_path: Path) -> None:
    approvals = tmp_path / "approvals.json"
    approval_id = "appr_" + ("d" * 32)
    pending_approval(approvals, approval_id)
    config = approvals_config(tmp_path, approvals)

    result = runner.invoke(
        app,
        ["approve", "allow", approval_id, "--config", str(config), "--by", "ana", "--comment", "ok"],
    )

    assert result.exit_code == 0
    assert "approved" in result.stdout


def test_approve_deny_success(tmp_path: Path) -> None:
    approvals = tmp_path / "approvals.json"
    approval_id = "appr_" + ("e" * 32)
    pending_approval(approvals, approval_id)
    config = approvals_config(tmp_path, approvals)

    result = runner.invoke(app, ["approve", "deny", approval_id, "--config", str(config)])

    assert result.exit_code == 0
    assert "denied" in result.stdout


def test_approve_allow_missing(tmp_path: Path) -> None:
    approvals = tmp_path / "approvals.json"
    approvals.write_text("{}", encoding="utf-8")
    config = approvals_config(tmp_path, approvals)

    result = runner.invoke(app, ["approve", "allow", "nope", "--config", str(config)])

    assert result.exit_code == 1
    assert "Approval not found" in result.stdout


def test_approve_serve_starts_ui(tmp_path: Path, monkeypatch) -> None:
    import uvicorn

    config = write(tmp_path, "mcpzt.yaml", dev_config())
    calls: dict[str, object] = {}

    def fake_run(app_obj, *, host, port):  # noqa: ANN001
        calls["host"] = host
        calls["port"] = port

    monkeypatch.setattr(uvicorn, "run", fake_run)

    result = runner.invoke(app, ["approve", "serve", "--config", str(config), "--port", "9100"])

    assert result.exit_code == 0
    assert calls["port"] == 9100


# --------------------------------------------------------------------------- #
# pack list / show / add
# --------------------------------------------------------------------------- #


def test_pack_list() -> None:
    result = runner.invoke(app, ["pack", "list"])

    assert result.exit_code == 0
    assert "github-readonly" in result.stdout


def test_pack_show_and_unknown() -> None:
    ok = runner.invoke(app, ["pack", "show", "github-readonly"])
    assert ok.exit_code == 0

    unknown = runner.invoke(app, ["pack", "show", "nope"])
    assert unknown.exit_code == 1
    assert "Unknown pack" in unknown.stdout


def test_pack_add_and_unknown(tmp_path: Path) -> None:
    output = tmp_path / "pack.yaml"
    ok = runner.invoke(app, ["pack", "add", "github-readonly", "--output", str(output)])
    assert ok.exit_code == 0
    assert output.exists()

    unknown = runner.invoke(
        app, ["pack", "add", "nope", "--output", str(tmp_path / "x.yaml")]
    )
    assert unknown.exit_code == 1
    assert "Unknown pack" in unknown.stdout


# --------------------------------------------------------------------------- #
# client config / import
# --------------------------------------------------------------------------- #


def test_client_config_output_write(tmp_path: Path) -> None:
    config = write(tmp_path, "mcpzt.yaml", dev_config())
    output = tmp_path / "client.json"

    result = runner.invoke(
        app, ["client", "config", "--config", str(config), "--output", str(output)]
    )

    assert result.exit_code == 0
    assert output.exists()


def test_client_config_invalid_kind(tmp_path: Path) -> None:
    config = write(tmp_path, "mcpzt.yaml", dev_config())

    result = runner.invoke(
        app, ["client", "config", "--config", str(config), "--kind", "emacs"]
    )

    assert result.exit_code == 1
    assert "Cannot generate client config" in result.stdout


def test_client_config_no_http_server(tmp_path: Path) -> None:
    config = write(
        tmp_path,
        "mcpzt.yaml",
        """
project:
  name: stdio-only
  environment: development
runtime:
  mode: stdio
  default_decision: deny
auth:
  mode: none
servers:
  - name: local
    transport: stdio
    command: [echo, hi]
policies: []
audit:
  destination: file
  path: ./a.jsonl
""",
    )

    result = runner.invoke(app, ["client", "config", "--config", str(config)])

    assert result.exit_code == 1
    assert "Cannot generate client config" in result.stdout


def test_client_import_output_exists_without_force(tmp_path: Path) -> None:
    source = tmp_path / "src.json"
    source.write_text(json.dumps({"mcpServers": {}}), encoding="utf-8")
    mcpzt_config = tmp_path / "mcpzt.yaml"
    mcpzt_config.write_text("existing", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "client",
            "import",
            "--source",
            str(source),
            "--mcpzt-config",
            str(mcpzt_config),
            "--client-output",
            str(tmp_path / "client.json"),
        ],
    )

    assert result.exit_code == 2


def test_client_import_error_for_bad_source(tmp_path: Path) -> None:
    source = tmp_path / "bad.json"
    source.write_text("{not valid json", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "client",
            "import",
            "--source",
            str(source),
            "--mcpzt-config",
            str(tmp_path / "mcpzt.yaml"),
            "--client-output",
            str(tmp_path / "client.json"),
        ],
    )

    assert result.exit_code == 1
    assert "Cannot import client config" in result.stdout


def test_client_import_with_discover(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "claude_desktop_config.json"
    source.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "pencil": {
                        "command": "/Applications/Pencil.app/mcp-server",
                        "args": ["--app", "desktop"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    mcpzt_config = tmp_path / "out" / "mcpzt.yaml"
    client_output = tmp_path / "out" / "client.json"

    monkeypatch.setattr(
        cli_main,
        "_discover_configured_servers",
        lambda base_config: [snapshot(base_config.servers[0].name, tools=[])],
    )

    result = runner.invoke(
        app,
        [
            "client",
            "import",
            "--source",
            str(source),
            "--mcpzt-config",
            str(mcpzt_config),
            "--client-output",
            str(client_output),
            "--discover",
            "--snapshot-dir",
            str(tmp_path / "snaps"),
        ],
    )

    assert result.exit_code == 0
    assert mcpzt_config.exists()
    assert (tmp_path / "snaps").exists()


# --------------------------------------------------------------------------- #
# doctor branches
# --------------------------------------------------------------------------- #


def test_doctor_invalid_config(tmp_path: Path) -> None:
    config = write(tmp_path, "mcpzt.yaml", ":bad:")

    result = runner.invoke(app, ["doctor", "--config", str(config)])

    assert result.exit_code == 1


def test_doctor_default_decision_allow_and_stdout_audit(tmp_path: Path) -> None:
    config = write(
        tmp_path,
        "mcpzt.yaml",
        """
project:
  name: d
  environment: development
runtime:
  default_decision: allow
auth:
  mode: none
servers:
  - name: github
    transport: http
    upstream: http://localhost:3001/mcp
policies: []
audit:
  destination: stdout
approvals:
  path: ./approvals.json
""",
    )

    result = runner.invoke(app, ["doctor", "--config", str(config)])

    assert "default_decision is allow" in result.stdout
    assert "audit writes to stdout" in result.stdout


def test_doctor_jwt_and_origins(tmp_path: Path) -> None:
    config = write(
        tmp_path,
        "mcpzt.yaml",
        f"""
project:
  name: jwt
  environment: production
runtime:
  default_decision: deny
  allowed_origins: [https://ok.example]
  public_base_url: https://mcpzt.example
auth:
  mode: jwt
  issuer: https://issuer.example
  audience: mcpzt
  jwks_url: https://issuer.example/jwks
  required_scopes: [mcpzt.use]
  trust_identity_headers: true
servers:
  - name: github
    transport: http
    upstream: https://github.example/mcp
policies: []
audit:
  destination: file
  path: {tmp_path / "audit.jsonl"}
approvals:
  path: {tmp_path / "approvals.json"}
""",
    )

    result = runner.invoke(app, ["doctor", "--config", str(config)])

    assert "jwt validation configured" in result.stdout
    assert "allowed origin" in result.stdout
    assert "trusts x-mcpzt identity headers" in result.stdout


def test_doctor_api_key_without_token(tmp_path: Path) -> None:
    config = write(
        tmp_path,
        "mcpzt.yaml",
        f"""
project:
  name: ak
  environment: development
runtime:
  default_decision: deny
auth:
  mode: api_key
  header: x-api-key
servers:
  - name: github
    transport: http
    upstream: https://github.example/mcp
policies: []
audit:
  destination: file
  path: {tmp_path / "audit.jsonl"}
approvals:
  path: {tmp_path / "approvals.json"}
""",
    )

    result = runner.invoke(app, ["doctor", "--config", str(config)])

    assert result.exit_code == 1
    assert "requires auth.token" in result.stdout


def test_doctor_parent_path_will_be_created(tmp_path: Path) -> None:
    config = write(
        tmp_path,
        "mcpzt.yaml",
        f"""
project:
  name: paths
  environment: development
runtime:
  default_decision: deny
auth:
  mode: none
servers:
  - name: github
    transport: http
    upstream: https://github.example/mcp
policies: []
audit:
  destination: file
  path: {tmp_path / "does-not-exist" / "audit.jsonl"}
approvals:
  path: {tmp_path / "approvals.json"}
""",
    )

    result = runner.invoke(app, ["doctor", "--config", str(config)])

    assert "will be created" in result.stdout


def test_doctor_jwt_missing(tmp_path: Path) -> None:
    config = write(
        tmp_path,
        "mcpzt.yaml",
        f"""
project:
  name: jwt
  environment: development
runtime:
  default_decision: deny
auth:
  mode: jwt
servers:
  - name: github
    transport: http
    upstream: https://github.example/mcp
policies: []
audit:
  destination: file
  path: {tmp_path / "audit.jsonl"}
approvals:
  path: {tmp_path / "approvals.json"}
""",
    )

    result = runner.invoke(app, ["doctor", "--config", str(config)])

    assert result.exit_code == 1
    assert "jwt requires" in result.stdout


def test_doctor_oidc_configured_and_missing(tmp_path: Path) -> None:
    ok = write(
        tmp_path,
        "ok.yaml",
        f"""
project:
  name: oidc
  environment: development
runtime:
  default_decision: deny
auth:
  mode: oidc
  issuer: https://issuer.example
servers:
  - name: github
    transport: http
    upstream: https://github.example/mcp
policies: []
audit:
  destination: file
  path: {tmp_path / "audit.jsonl"}
approvals:
  path: {tmp_path / "approvals.json"}
""",
    )
    result_ok = runner.invoke(app, ["doctor", "--config", str(ok)])
    assert "oidc validation configured" in result_ok.stdout

    missing = write(
        tmp_path,
        "missing.yaml",
        f"""
project:
  name: oidc
  environment: development
runtime:
  default_decision: deny
auth:
  mode: oidc
servers:
  - name: github
    transport: http
    upstream: https://github.example/mcp
policies: []
audit:
  destination: file
  path: {tmp_path / "audit.jsonl"}
approvals:
  path: {tmp_path / "approvals.json"}
""",
    )
    result_missing = runner.invoke(app, ["doctor", "--config", str(missing)])
    assert result_missing.exit_code == 1
    assert "oidc requires" in result_missing.stdout


def test_doctor_static_token_inline_and_placeholder(tmp_path: Path) -> None:
    inline = write(
        tmp_path,
        "inline.yaml",
        f"""
project:
  name: st
  environment: development
runtime:
  default_decision: deny
auth:
  mode: static_token
  token: a-real-inline-token
servers:
  - name: github
    transport: http
    upstream: https://github.example/mcp
policies: []
audit:
  destination: file
  path: {tmp_path / "audit.jsonl"}
approvals:
  path: {tmp_path / "approvals.json"}
""",
    )
    result_inline = runner.invoke(app, ["doctor", "--config", str(inline)])
    assert "inline auth.token should not be committed" in result_inline.stdout

    placeholder = write(
        tmp_path,
        "placeholder.yaml",
        f"""
project:
  name: st
  environment: development
runtime:
  default_decision: deny
auth:
  mode: static_token
  token: change-me
servers:
  - name: github
    transport: http
    upstream: https://github.example/mcp
policies: []
audit:
  destination: file
  path: {tmp_path / "audit.jsonl"}
approvals:
  path: {tmp_path / "approvals.json"}
""",
    )
    result_placeholder = runner.invoke(app, ["doctor", "--config", str(placeholder)])
    assert result_placeholder.exit_code == 1
    assert "replace placeholder auth.token" in result_placeholder.stdout


def test_doctor_static_token_from_secret_file(tmp_path: Path) -> None:
    secret = tmp_path / "secret.txt"
    secret.write_text("value", encoding="utf-8")
    config = write(
        tmp_path,
        "mcpzt.yaml",
        f"""
project:
  name: st
  environment: development
runtime:
  default_decision: deny
auth:
  mode: static_token
  token: "file:{secret}"
servers:
  - name: github
    transport: http
    upstream: https://github.example/mcp
policies: []
audit:
  destination: file
  path: {tmp_path / "audit.jsonl"}
approvals:
  path: {tmp_path / "approvals.json"}
""",
    )

    result = runner.invoke(app, ["doctor", "--config", str(config)])

    assert "from secret reference" in result.stdout


def test_doctor_secret_source_failures(tmp_path: Path) -> None:
    missing_file = write(
        tmp_path,
        "missing_file.yaml",
        f"""
project:
  name: st
  environment: development
runtime:
  default_decision: deny
auth:
  mode: static_token
  token: "file:///nonexistent/secret.txt"
servers:
  - name: github
    transport: http
    upstream: https://github.example/mcp
policies: []
audit:
  destination: file
  path: {tmp_path / "audit.jsonl"}
approvals:
  path: {tmp_path / "approvals.json"}
""",
    )
    result_file = runner.invoke(app, ["doctor", "--config", str(missing_file)])
    assert result_file.exit_code == 1
    assert "missing file secret" in result_file.stdout

    op_secret = write(
        tmp_path,
        "op.yaml",
        f"""
project:
  name: st
  environment: development
runtime:
  default_decision: deny
auth:
  mode: static_token
  token: "op://vault/item/field"
servers:
  - name: github
    transport: http
    upstream: https://github.example/mcp
policies: []
audit:
  destination: file
  path: {tmp_path / "audit.jsonl"}
approvals:
  path: {tmp_path / "approvals.json"}
""",
    )
    result_op = runner.invoke(app, ["doctor", "--config", str(op_secret)])
    assert result_op.exit_code == 1
    assert "CLI not found" in result_op.stdout


def test_doctor_upstream_headers(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MCPZT_DOCTOR_HEADER", "value")
    ok = write(
        tmp_path,
        "ok.yaml",
        f"""
project:
  name: hdr
  environment: development
runtime:
  default_decision: deny
auth:
  mode: none
servers:
  - name: github
    transport: http
    upstream: https://github.example/mcp
    upstream_headers:
      Authorization: Bearer ${{MCPZT_DOCTOR_HEADER}}
policies: []
audit:
  destination: file
  path: {tmp_path / "audit.jsonl"}
approvals:
  path: {tmp_path / "approvals.json"}
""",
    )
    result_ok = runner.invoke(app, ["doctor", "--config", str(ok)])
    assert "configured upstream header" in result_ok.stdout

    inline = write(
        tmp_path,
        "inline.yaml",
        f"""
project:
  name: hdr
  environment: development
runtime:
  default_decision: deny
auth:
  mode: none
servers:
  - name: github
    transport: http
    upstream: https://github.example/mcp
    upstream_headers:
      Authorization: Bearer inline-secret
policies: []
audit:
  destination: file
  path: {tmp_path / "audit.jsonl"}
approvals:
  path: {tmp_path / "approvals.json"}
""",
    )
    result_inline = runner.invoke(app, ["doctor", "--config", str(inline)])
    assert "inline sensitive upstream header" in result_inline.stdout

    monkeypatch.delenv("MCPZT_DOCTOR_HEADER", raising=False)
    unset = write(
        tmp_path,
        "unset.yaml",
        f"""
project:
  name: hdr
  environment: development
runtime:
  default_decision: deny
auth:
  mode: none
servers:
  - name: github
    transport: http
    upstream: https://github.example/mcp
    upstream_headers:
      Authorization: Bearer ${{MCPZT_DOCTOR_HEADER}}
policies: []
audit:
  destination: file
  path: {tmp_path / "audit.jsonl"}
approvals:
  path: {tmp_path / "approvals.json"}
""",
    )
    result_unset = runner.invoke(app, ["doctor", "--config", str(unset)])
    assert result_unset.exit_code == 1
    assert "unset env" in result_unset.stdout


def test_doctor_invalid_http_upstream(tmp_path: Path) -> None:
    config = write(
        tmp_path,
        "mcpzt.yaml",
        f"""
project:
  name: bad-upstream
  environment: development
runtime:
  default_decision: deny
auth:
  mode: none
servers:
  - name: github
    transport: http
    upstream: not-a-url
policies: []
audit:
  destination: file
  path: {tmp_path / "audit.jsonl"}
approvals:
  path: {tmp_path / "approvals.json"}
""",
    )

    result = runner.invoke(app, ["doctor", "--config", str(config)])

    assert result.exit_code == 1
    assert "invalid HTTP upstream URL" in result.stdout


def test_doctor_stdio_stdout_audit_conflict(tmp_path: Path) -> None:
    config = write(
        tmp_path,
        "mcpzt.yaml",
        """
project:
  name: stdio
  environment: development
runtime:
  mode: stdio
  default_decision: deny
auth:
  mode: none
servers:
  - name: local
    transport: stdio
    command: [echo, hi]
policies: []
audit:
  destination: stdout
""",
    )

    result = runner.invoke(app, ["doctor", "--config", str(config)])

    assert result.exit_code == 1
    assert "stdio mode cannot use audit.destination stdout" in result.stdout


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #


def test_upstream_for_and_server_helpers(tmp_path: Path) -> None:
    from mcp_zero_trust_layer.config.models import ServerConfig

    http_server = ServerConfig(name="h", transport="http", upstream="http://x/mcp")
    stdio_server = ServerConfig(name="s", transport="stdio", command=["echo", "hi"])
    assert cli_main._upstream_for(http_server) is not None
    stdio_upstream = cli_main._upstream_for(stdio_server)
    assert hasattr(stdio_upstream, "close")
    stdio_upstream.close()


def test_default_claude_desktop_config_path() -> None:
    assert cli_main._default_claude_desktop_config().name.endswith(".json")


def test_parse_cli_timestamp_none() -> None:
    assert cli_main._parse_cli_timestamp(None) is None


def test_print_imported_servers_ignores_non_tuple() -> None:
    # Defensive early-return guard for non-tuple input.
    assert cli_main._print_imported_servers(None) is None
