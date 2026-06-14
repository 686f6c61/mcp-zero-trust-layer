from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcp_zero_trust_layer.capabilities.discovery import CapabilitySnapshot
from mcp_zero_trust_layer.cli import main as cli_main
from mcp_zero_trust_layer.cli.main import app


runner = CliRunner()


def test_config_schema_prints_json_schema() -> None:
    result = runner.invoke(app, ["config", "schema"])

    assert result.exit_code == 0
    schema = json.loads(result.stdout)
    assert schema["title"] == "MCPZTConfig"
    assert "servers" in schema["properties"]


def test_config_schema_writes_output(tmp_path: Path) -> None:
    output = tmp_path / "schema.json"

    result = runner.invoke(app, ["config", "schema", "--output", str(output)])

    assert result.exit_code == 0
    assert json.loads(output.read_text(encoding="utf-8"))["title"] == "MCPZTConfig"


def test_doctor_warns_without_config() -> None:
    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 0
    assert "package" in result.stdout
    assert "pass --config" in result.stdout


def test_doctor_validates_config(tmp_path: Path) -> None:
    config = tmp_path / "mcpzt.yaml"
    config.write_text(
        """
project:
  name: cli-test
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
  path: ./audit.jsonl
approvals:
  path: ./approvals.json
""",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["doctor", "--config", str(config)])

    assert result.exit_code == 0
    assert "cli-test" in result.stdout
    assert "default_decision is deny" in result.stdout


def test_doctor_fails_for_missing_stdio_command(tmp_path: Path) -> None:
    config = tmp_path / "mcpzt.yaml"
    config.write_text(
        """
project:
  name: cli-test
  environment: development
runtime:
  mode: stdio
  default_decision: deny
auth:
  mode: none
servers:
  - name: missing
    transport: stdio
    command:
      - definitely-not-a-real-mcp-command
policies: []
audit:
  destination: file
  path: ./audit.jsonl
""",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["doctor", "--config", str(config)])

    assert result.exit_code == 1
    assert "command not found" in result.stdout


def test_doctor_checks_secret_environment_variables(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("MCPZT_TEST_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("MCPZT_TEST_UPSTREAM_TOKEN", raising=False)
    config = tmp_path / "mcpzt.yaml"
    config.write_text(
        """
project:
  name: cli-test
  environment: development
runtime:
  default_decision: deny
auth:
  mode: api_key
  header: x-api-key
  token_env: MCPZT_TEST_AUTH_TOKEN
servers:
  - name: github
    transport: http
    upstream: http://localhost:3001/mcp
    upstream_headers:
      Authorization: Bearer ${MCPZT_TEST_UPSTREAM_TOKEN}
policies: []
audit:
  destination: file
  path: ./audit.jsonl
""",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["doctor", "--config", str(config)])

    assert result.exit_code == 1
    assert "MCPZT_TEST_AUTH_TOKEN" in result.stdout
    assert "MCPZT_TEST_UPSTREAM_TOKEN" in result.stdout

    monkeypatch.setenv("MCPZT_TEST_AUTH_TOKEN", "auth-secret")
    monkeypatch.setenv("MCPZT_TEST_UPSTREAM_TOKEN", "upstream-secret")

    result = runner.invoke(app, ["doctor", "--config", str(config)])

    assert result.exit_code == 0
    assert "api_key configured from environment" in result.stdout
    assert "configured upstream header" in result.stdout


def test_doctor_fails_for_production_dry_run_override(tmp_path: Path) -> None:
    config = tmp_path / "mcpzt.yaml"
    config.write_text(
        """
project:
  name: prod-test
  environment: production
runtime:
  default_decision: deny
  dry_run: true
  allow_dry_run_in_production: true
  public_base_url: https://mcpzt.example
auth:
  mode: static_token
  token: secret-value
servers:
  - name: github
    transport: http
    upstream: http://localhost:3001/mcp
policies: []
audit:
  destination: file
  path: ./audit.jsonl
""",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["doctor", "--config", str(config)])

    assert result.exit_code == 1
    assert "production dry_run is enabled" in result.stdout


def test_doctor_strict_fails_on_warnings(tmp_path: Path) -> None:
    config = tmp_path / "mcpzt.yaml"
    config.write_text(
        """
project:
  name: strict-test
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
  path: ./audit.jsonl
""",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["doctor", "--strict", "--config", str(config)])

    assert result.exit_code == 1
    assert "auth.mode is none" in result.stdout


def test_doctor_production_requires_production_environment(tmp_path: Path) -> None:
    config = tmp_path / "mcpzt.yaml"
    config.write_text(
        """
project:
  name: production-check
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
  path: ./audit.jsonl
""",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["doctor", "--production", "--config", str(config)])

    assert result.exit_code == 1
    assert "--production requires project.environment:" in result.stdout
    assert "production, got development" in result.stdout


def test_policy_explain_prints_selected_policy(tmp_path: Path) -> None:
    config = tmp_path / "mcpzt.yaml"
    config.write_text(
        """
project:
  name: explain-test
  environment: development
runtime:
  default_decision: deny
auth:
  mode: none
servers:
  - name: github
    transport: http
    upstream: http://localhost:3001/mcp
policies:
  - id: allow-search
    effect: allow
    match:
      server: github
      capability_type: tool
      capability: github.search_issues
audit:
  destination: file
  path: ./audit.jsonl
""",
        encoding="utf-8",
    )

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
            "--capability",
            "github.search_issues",
        ],
    )

    assert result.exit_code == 0
    explanation = json.loads(result.stdout)
    assert explanation["selected_policy_id"] == "allow-search"
    assert explanation["decision"]["decision"] == "allow"


def test_client_config_generates_mcp_remote_config(tmp_path: Path) -> None:
    config = tmp_path / "mcpzt.yaml"
    config.write_text(
        """
project:
  name: client-test
  environment: development
runtime:
  default_decision: deny
auth:
  mode: none
servers:
  - name: github
    transport: http
    upstream: http://localhost:3001/mcp
  - name: postgres
    transport: http
    upstream: http://localhost:3002/mcp
policies: []
audit:
  destination: file
  path: ./audit.jsonl
""",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "client",
            "config",
            "--config",
            str(config),
            "--base-url",
            "https://mcpzt.example",
        ],
    )

    assert result.exit_code == 0
    rendered = json.loads(result.stdout)
    assert rendered["mcpServers"]["mcpzt-github"]["args"][-1] == (
        "https://mcpzt.example/mcp/github"
    )
    assert rendered["mcpServers"]["mcpzt-postgres"]["command"] == "npx"


def test_client_config_generates_claude_code_commands(tmp_path: Path) -> None:
    config = tmp_path / "mcpzt.yaml"
    config.write_text(
        """
project:
  name: client-test
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
  path: ./audit.jsonl
""",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "client",
            "config",
            "--config",
            str(config),
            "--base-url",
            "https://mcpzt.example",
            "--kind",
            "claude-code",
        ],
    )

    assert result.exit_code == 0
    assert result.stdout.strip() == (
        "claude mcp add mcpzt-github --transport http https://mcpzt.example/mcp/github"
    )


def test_config_lint_reports_warnings_as_json(tmp_path: Path) -> None:
    config = tmp_path / "mcpzt.yaml"
    config.write_text(
        """
project:
  name: lint-test
  environment: development
runtime:
  default_decision: allow
auth:
  mode: none
servers:
  - name: github
    transport: http
    upstream: http://localhost:3001/mcp
policies:
  - id: allow-everything
    effect: allow
    match: {}
audit:
  destination: file
  path: ./audit.jsonl
""",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["config", "lint", "--format", "json", "--config", str(config)])

    assert result.exit_code == 0
    findings = json.loads(result.stdout)
    assert {finding["rule"] for finding in findings} >= {
        "runtime.default_decision",
        "auth.mode",
        "policies.allow-everything",
    }

    strict = runner.invoke(
        app, ["config", "lint", "--strict", "--format", "json", "--config", str(config)]
    )
    assert strict.exit_code == 1


def test_approve_list_prints_full_approval_id(tmp_path: Path) -> None:
    config = tmp_path / "mcpzt.yaml"
    approvals = tmp_path / "approvals.json"
    approval_id = "appr_" + ("a" * 32)
    config.write_text(
        f"""
project:
  name: approvals-test
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
  path: ./audit.jsonl
approvals:
  path: {approvals}
""",
        encoding="utf-8",
    )
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
                    "expires_at": "2026-06-14T09:15:00+00:00",
                }
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["approve", "list", "--config", str(config)])

    assert result.exit_code == 0
    assert approval_id in result.stdout


def test_approve_list_outputs_json(tmp_path: Path) -> None:
    config = tmp_path / "mcpzt.yaml"
    approvals = tmp_path / "approvals.json"
    approval_id = "appr_" + ("b" * 32)
    config.write_text(
        f"""
project:
  name: approvals-json-test
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
  path: ./audit.jsonl
approvals:
  path: {approvals}
""",
        encoding="utf-8",
    )
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
                    "expires_at": "2026-06-14T09:15:00+00:00",
                }
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["approve", "list", "--format", "json", "--config", str(config)])

    assert result.exit_code == 0
    approvals_json = json.loads(result.stdout)
    assert approvals_json[0]["id"] == approval_id
    assert approvals_json[0]["status"] == "pending"


def test_approve_list_empty_json_does_not_create_lock_file(tmp_path: Path) -> None:
    config = tmp_path / "mcpzt.yaml"
    approvals = tmp_path / "missing-approvals.json"
    config.write_text(
        f"""
project:
  name: approvals-empty-test
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
  path: ./audit.jsonl
approvals:
  path: {approvals}
""",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["approve", "list", "--format", "json", "--config", str(config)])

    assert result.exit_code == 0
    assert json.loads(result.stdout) == []
    assert not approvals.exists()
    assert not Path(f"{approvals}.lock").exists()


def test_demo_writes_runnable_demo_files(tmp_path: Path) -> None:
    output = tmp_path / "demo"

    result = runner.invoke(app, ["demo", "--output", str(output)])

    assert result.exit_code == 0
    assert (output / "mcpzt.yaml").exists()
    assert (output / "fake_mcp.py").exists()
    assert (output / "demo_client.py").exists()
    assert (output / "run_demo.sh").exists()
    assert "demo.safe_echo" in (output / "mcpzt.yaml").read_text(encoding="utf-8")
    assert 'cd "$DIR"' in (output / "run_demo.sh").read_text(encoding="utf-8")


def test_scan_exits_two_for_high_findings(tmp_path: Path) -> None:
    config = tmp_path / "mcpzt.yaml"
    snapshot = tmp_path / "snapshot.json"
    config.write_text(
        """
project:
  name: scan-test
  environment: development
runtime:
  default_decision: deny
auth:
  mode: none
servers:
  - name: github
    transport: http
    upstream: http://localhost:3001/mcp
policies:
  - id: allow-all-tools
    effect: allow
    match:
      server: github
      capability_type: tool
audit:
  destination: file
  path: ./audit.jsonl
""",
        encoding="utf-8",
    )
    snapshot.write_text(
        json.dumps(
            {
                "server": "github",
                "discovered_at": "2026-01-01T00:00:00Z",
                "tools": [
                    {
                        "name": "github.delete_repository",
                        "description": "Delete a repository.",
                    }
                ],
                "resources": [],
                "prompts": [],
                "errors": {},
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(app, ["scan", "--config", str(config), "--snapshot", str(snapshot)])

    assert result.exit_code == 2
    report = json.loads(result.stdout)
    assert report["findings"][0]["rule_id"] == "missing-capability-metadata"
    assert any(finding["rule_id"] == "dangerous-tool-allowed" for finding in report["findings"])


def test_approve_list_outputs_json_from_sqlite_backend(tmp_path: Path) -> None:
    config = tmp_path / "mcpzt.yaml"
    approvals = tmp_path / "approvals.sqlite3"
    config.write_text(
        f"""
project:
  name: approvals-sqlite-test
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
  path: ./audit.jsonl
approvals:
  backend: sqlite
  path: {approvals}
""",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["approve", "list", "--format", "json", "--config", str(config)])

    assert result.exit_code == 0
    assert json.loads(result.stdout) == []
    assert approvals.exists()


def test_audit_search_outputs_filtered_json(tmp_path: Path) -> None:
    config = tmp_path / "mcpzt.yaml"
    audit = tmp_path / "audit.jsonl"
    config.write_text(
        f"""
project:
  name: audit-search-test
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
""",
        encoding="utf-8",
    )
    audit.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "timestamp": "2026-06-14T10:00:00+00:00",
                        "event_type": "policy_decision",
                        "server": "github",
                        "decision": "allow",
                        "policy_id": "allow-search",
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-06-14T10:01:00+00:00",
                        "event_type": "policy_decision",
                        "server": "github",
                        "decision": "deny",
                        "policy_id": "deny-delete",
                    }
                ),
            ]
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "audit",
            "search",
            "--config",
            str(config),
            "--decision",
            "deny",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    events = json.loads(result.stdout)
    assert [event["policy_id"] for event in events] == ["deny-delete"]


def test_policy_coverage_outputs_json(tmp_path: Path) -> None:
    config = tmp_path / "mcpzt.yaml"
    config.write_text(
        """
project:
  name: coverage-test
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
      github.search_issues:
        action: code.read
        risk: low
        access: read
policies:
  - id: allow-search
    effect: allow
    match:
      server: github
      capability: github.search_issues
audit:
  destination: file
  path: ./audit.jsonl
""",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["policy", "coverage", "--config", str(config), "--format", "json"])

    assert result.exit_code == 0
    report = json.loads(result.stdout)
    assert report["items"][0]["capability"] == "github.search_issues"
    assert report["items"][0]["decision"] == "allow"


def test_onboard_generates_config_from_server_specs(tmp_path: Path, monkeypatch) -> None:
    output = tmp_path / "generated.yaml"

    def fake_discover(config, server_name, upstream):  # noqa: ANN001
        return CapabilitySnapshot(
            server=server_name,
            discovered_at="2026-06-14T10:00:00Z",
            tools=[{"name": "github.search_issues", "description": "Search issues"}],
            resources=[],
            prompts=[],
        )

    monkeypatch.setattr("mcp_zero_trust_layer.cli.main.discover_capabilities", fake_discover)

    result = runner.invoke(
        app,
        [
            "onboard",
            "--server",
            "github=http://localhost:3001/mcp",
            "--output",
            str(output),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert "github.search_issues" in output.read_text(encoding="utf-8")
    report = json.loads(result.stdout[result.stdout.index("{") :])
    assert report["servers"][0]["server"] == "github"


def test_client_import_command_writes_wrapped_configs(tmp_path: Path) -> None:
    source = tmp_path / "claude_desktop_config.json"
    mcpzt_config = tmp_path / "mcpzt.yaml"
    client_output = tmp_path / "claude_desktop_config.mcpzt.json"
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
            "--wrapper-command",
            "/usr/local/bin/mcpzt",
        ],
    )

    assert result.exit_code == 0
    assert "Wrote MCPZT config" in result.stdout
    assert "pencil" in mcpzt_config.read_text(encoding="utf-8")
    rendered = json.loads(client_output.read_text(encoding="utf-8"))
    assert rendered["mcpServers"]["pencil"]["command"] == "/usr/local/bin/mcpzt"
    assert rendered["mcpServers"]["pencil"]["args"][-1] == "pencil"


def test_table_json_commands_reject_unknown_format(tmp_path: Path) -> None:
    config = tmp_path / "mcpzt.yaml"
    audit = tmp_path / "audit.jsonl"
    config.write_text(
        f"""
project:
  name: invalid-format-test
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
      github.search_issues:
        action: code.read
        risk: low
        access: read
policies:
  - id: allow-search
    effect: allow
    match:
      server: github
      capability: github.search_issues
audit:
  destination: file
  path: {audit}
approvals:
  path: {tmp_path / "approvals.json"}
""",
        encoding="utf-8",
    )
    audit.write_text(
        json.dumps(
            {
                "timestamp": "2026-06-14T10:00:00+00:00",
                "event_type": "policy_decision",
                "server": "github",
                "decision": "allow",
            }
        ),
        encoding="utf-8",
    )

    commands = [
        ["config", "lint", "--config", str(config), "--format", "xml"],
        ["policy", "coverage", "--config", str(config), "--format", "xml"],
        ["policy", "risks", "--config", str(config), "--format", "xml"],
        ["policy", "unused", "--config", str(config), "--format", "xml"],
        ["audit", "search", "--config", str(config), "--format", "xml"],
        ["approve", "list", "--config", str(config), "--format", "xml"],
    ]

    for command in commands:
        result = runner.invoke(app, command)
        assert result.exit_code == 1
        assert "--format must be table or json" in result.stdout


def test_onboard_table_dry_run_and_invalid_format(tmp_path: Path, monkeypatch) -> None:
    def fake_discover(config, server_name, upstream):  # noqa: ANN001
        return CapabilitySnapshot(
            server=server_name,
            discovered_at="2026-06-14T10:00:00Z",
            tools=[{"name": "github.delete_repository", "description": "Delete repository"}],
            resources=[],
            prompts=[],
            errors={"resources": "not supported"},
        )

    monkeypatch.setattr("mcp_zero_trust_layer.cli.main.discover_capabilities", fake_discover)

    dry_run = runner.invoke(
        app,
        [
            "onboard",
            "--server",
            "github=http://localhost:3001/mcp",
            "--output",
            str(tmp_path / "generated.yaml"),
            "--dry-run",
        ],
    )
    invalid = runner.invoke(
        app,
        [
            "onboard",
            "--server",
            "github=http://localhost:3001/mcp",
            "--output",
            str(tmp_path / "generated.yaml"),
            "--dry-run",
            "--format",
            "xml",
        ],
    )

    assert dry_run.exit_code == 0
    assert "github.delete_repository" in dry_run.stdout
    assert "Generated policies" in dry_run.stdout
    assert "resources" in dry_run.stdout
    assert invalid.exit_code == 1
    assert "--format must be table or json" in invalid.stdout


def test_onboard_existing_output_without_force_fails(tmp_path: Path, monkeypatch) -> None:
    output = tmp_path / "generated.yaml"
    output.write_text("existing", encoding="utf-8")

    def fake_discover(config, server_name, upstream):  # noqa: ANN001
        return CapabilitySnapshot(
            server=server_name,
            discovered_at="2026-06-14T10:00:00Z",
            tools=[],
            resources=[],
            prompts=[],
        )

    monkeypatch.setattr("mcp_zero_trust_layer.cli.main.discover_capabilities", fake_discover)

    result = runner.invoke(
        app,
        [
            "onboard",
            "--server",
            "github=http://localhost:3001/mcp",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 2
    assert result.exception is not None


def test_onboard_private_helpers_handle_empty_shapes(tmp_path: Path) -> None:
    cli_main._emit_onboard_config(
        "project:\n  name: dry\n",
        snapshots=[],
        output=tmp_path / "dry.yaml",
        force=False,
        dry_run=True,
        write_snapshots=True,
        snapshot_dir=tmp_path / "snapshots",
    )
    cli_main._write_onboard_snapshots(
        [],
        write_snapshots=False,
        snapshot_dir=tmp_path / "snapshots",
    )
    cli_main._print_onboard_report({"servers": "not-a-list", "generated_policies": [], "recommendations": []})

    with pytest.raises(cli_main.typer.Exit):
        cli_main._emit_onboard_report({}, "{}", "xml")

    assert cli_main._onboard_error_summary("not-a-dict") == ""
    assert cli_main._onboard_error_summary({"tools": "missing"}) == "tools"
