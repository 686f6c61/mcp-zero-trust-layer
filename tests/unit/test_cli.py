from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

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
