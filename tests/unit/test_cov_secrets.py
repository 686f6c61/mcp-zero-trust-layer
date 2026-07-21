from __future__ import annotations

import subprocess
import types

import pytest

from mcp_zero_trust_layer.config import secrets
from mcp_zero_trust_layer.config.secrets import (
    SecretError,
    _select_json_field,
    _split_reference,
    referenced_env_vars,
    referenced_secret_sources,
    resolve_secret_value,
    secret_provider_available,
)


def _fake_run(stdout: str):
    def runner(*args, **kwargs):
        return types.SimpleNamespace(stdout=stdout)

    return runner


def test_resolve_env_prefix(monkeypatch) -> None:
    monkeypatch.setenv("MCPZT_COV_ENV", "value")
    assert resolve_secret_value("env:MCPZT_COV_ENV", field="f") == "value"


def test_resolve_env_prefix_empty_name() -> None:
    with pytest.raises(SecretError, match="empty environment variable name"):
        resolve_secret_value("env:", field="f")


def test_resolve_env_prefix_unset(monkeypatch) -> None:
    monkeypatch.delenv("MCPZT_COV_MISSING", raising=False)
    with pytest.raises(SecretError, match="unset environment variable"):
        resolve_secret_value("env:MCPZT_COV_MISSING", field="f")


def test_resolve_braces_substitution(monkeypatch) -> None:
    monkeypatch.setenv("MCPZT_COV_A", "aa")
    monkeypatch.setenv("MCPZT_COV_B", "bb")
    assert resolve_secret_value("${MCPZT_COV_A}-${MCPZT_COV_B}", field="f") == "aa-bb"


def test_resolve_file_prefix(tmp_path) -> None:
    secret = tmp_path / "s.txt"
    secret.write_text("filesecret\n", encoding="utf-8")
    assert resolve_secret_value(f"file:{secret}", field="f") == "filesecret"


def test_resolve_file_url_scheme(tmp_path) -> None:
    secret = tmp_path / "s.txt"
    secret.write_text("urlsecret\n", encoding="utf-8")
    assert resolve_secret_value(f"file://{secret}", field="f") == "urlsecret"


def test_resolve_file_unreadable(tmp_path) -> None:
    with pytest.raises(SecretError, match="unreadable secret file"):
        resolve_secret_value(f"file:{tmp_path / 'missing.txt'}", field="f")


def test_resolve_file_empty(tmp_path) -> None:
    secret = tmp_path / "empty.txt"
    secret.write_text("   \n", encoding="utf-8")
    with pytest.raises(SecretError, match="empty secret file"):
        resolve_secret_value(f"file:{secret}", field="f")


def test_resolve_op_prefix(monkeypatch) -> None:
    monkeypatch.setattr(secrets.subprocess, "run", _fake_run("opsecret\n"))
    assert resolve_secret_value("op://vault/item/field", field="f") == "opsecret"


def test_resolve_aws_prefix_plain(monkeypatch) -> None:
    monkeypatch.setattr(secrets.subprocess, "run", _fake_run("awssecret\n"))
    assert resolve_secret_value("aws-sm://mysecret", field="f") == "awssecret"


def test_resolve_aws_prefix_json_field(monkeypatch) -> None:
    monkeypatch.setattr(secrets.subprocess, "run", _fake_run('{"password": "pw"}'))
    assert resolve_secret_value("aws-sm://mysecret#password", field="f") == "pw"


def test_resolve_vault_prefix(monkeypatch) -> None:
    monkeypatch.setattr(secrets.subprocess, "run", _fake_run("vaultsecret\n"))
    assert resolve_secret_value("vault://secret/path#token", field="f") == "vaultsecret"


def test_resolve_vault_prefix_default_field(monkeypatch) -> None:
    captured: dict[str, list[str]] = {}

    def runner(command, *args, **kwargs):
        captured["command"] = command
        return types.SimpleNamespace(stdout="v\n")

    monkeypatch.setattr(secrets.subprocess, "run", runner)
    assert resolve_secret_value("vault://secret/path", field="f") == "v"
    assert "-field=value" in captured["command"]


def test_command_secret_cli_not_installed(monkeypatch) -> None:
    def runner(*args, **kwargs):
        raise FileNotFoundError()

    monkeypatch.setattr(secrets.subprocess, "run", runner)
    with pytest.raises(SecretError, match="CLI is not installed"):
        resolve_secret_value("op://a/b/c", field="f")


def test_command_secret_timeout(monkeypatch) -> None:
    def runner(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=["op"], timeout=10)

    monkeypatch.setattr(secrets.subprocess, "run", runner)
    with pytest.raises(SecretError, match="timed out"):
        resolve_secret_value("op://a/b/c", field="f")


def test_command_secret_called_process_error(monkeypatch) -> None:
    def runner(*args, **kwargs):
        raise subprocess.CalledProcessError(returncode=1, cmd=["op"])

    monkeypatch.setattr(secrets.subprocess, "run", runner)
    with pytest.raises(SecretError, match="could not read secret"):
        resolve_secret_value("op://a/b/c", field="f")


def test_command_secret_empty_output(monkeypatch) -> None:
    monkeypatch.setattr(secrets.subprocess, "run", _fake_run("   \n"))
    with pytest.raises(SecretError, match="empty secret"):
        resolve_secret_value("op://a/b/c", field="f")


def test_referenced_env_vars() -> None:
    assert referenced_env_vars(None) == []
    assert referenced_env_vars("") == []
    assert referenced_env_vars("env:NAME") == ["NAME"]
    assert referenced_env_vars("${A}-${B}") == ["A", "B"]


def test_referenced_secret_sources() -> None:
    assert referenced_secret_sources(None) == []
    assert referenced_secret_sources("env:NAME") == [("env", "NAME")]
    assert referenced_secret_sources("file:/x") == [("file", "file:/x")]
    assert referenced_secret_sources("op://a/b/c") == [("op", "op://a/b/c")]
    assert referenced_secret_sources("aws-sm://x") == [("aws-sm", "aws-sm://x")]
    assert referenced_secret_sources("vault://x") == [("vault", "vault://x")]


def test_secret_provider_available(monkeypatch) -> None:
    assert secret_provider_available("env") is True
    assert secret_provider_available("file") is True
    monkeypatch.setattr(secrets.shutil, "which", lambda name: "/usr/bin/" + name)
    assert secret_provider_available("op") is True
    assert secret_provider_available("aws-sm") is True
    assert secret_provider_available("vault") is True
    monkeypatch.setattr(secrets.shutil, "which", lambda name: None)
    assert secret_provider_available("op") is False
    assert secret_provider_available("aws-sm") is False
    assert secret_provider_available("vault") is False
    assert secret_provider_available("unknown") is False


def test_split_reference() -> None:
    assert _split_reference("path") == ("path", None)
    assert _split_reference("path#field") == ("path", "field")
    assert _split_reference("path#") == ("path", None)


def test_select_json_field() -> None:
    assert _select_json_field("value", None, field="f") == "value"
    assert _select_json_field('{"k": "v"}', "k", field="f") == "v"


def test_select_json_field_invalid_json() -> None:
    with pytest.raises(SecretError, match="expected JSON secret material"):
        _select_json_field("not-json", "k", field="f")


def test_select_json_field_missing_key() -> None:
    with pytest.raises(SecretError, match="could not find"):
        _select_json_field('{"other": "v"}', "k", field="f")


def test_select_json_field_non_dict() -> None:
    with pytest.raises(SecretError, match="could not find"):
        _select_json_field('["a"]', "k", field="f")
