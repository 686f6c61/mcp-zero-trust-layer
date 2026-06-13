from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse


class SecretError(ValueError):
    pass


ENV_REF_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def resolve_secret_value(value: str, *, field: str) -> str:
    """Resolve env-backed config values without logging the resulting secret."""
    if value.startswith("env:"):
        return _read_env(value.removeprefix("env:"), field=field)
    if value.startswith("file:"):
        return _read_file_secret(value, field=field)
    if value.startswith("op://"):
        return _read_command_secret(["op", "read", value], provider="1Password", field=field)
    if value.startswith("aws-sm://"):
        return _read_aws_secret(value, field=field)
    if value.startswith("vault://"):
        return _read_vault_secret(value, field=field)

    def replace(match: re.Match[str]) -> str:
        return _read_env(match.group(1), field=field)

    return ENV_REF_RE.sub(replace, value)


def referenced_env_vars(value: str | None) -> list[str]:
    if not value:
        return []
    refs = ENV_REF_RE.findall(value)
    if value.startswith("env:"):
        refs.append(value.removeprefix("env:"))
    return refs


def referenced_secret_sources(value: str | None) -> list[tuple[str, str]]:
    if not value:
        return []
    refs = [("env", name) for name in referenced_env_vars(value)]
    for prefix, kind in [
        ("file:", "file"),
        ("op://", "op"),
        ("aws-sm://", "aws-sm"),
        ("vault://", "vault"),
    ]:
        if value.startswith(prefix):
            refs.append((kind, value))
    return refs


def secret_provider_available(kind: str) -> bool:
    if kind == "env":
        return True
    if kind == "file":
        return True
    if kind == "op":
        return shutil.which("op") is not None
    if kind == "aws-sm":
        return shutil.which("aws") is not None
    if kind == "vault":
        return shutil.which("vault") is not None
    return False


def _read_env(name: str, *, field: str) -> str:
    if not name:
        raise SecretError(f"{field} references an empty environment variable name")
    value = os.environ.get(name)
    if value is None or value == "":
        raise SecretError(f"{field} references unset environment variable: {name}")
    return value


def _read_file_secret(reference: str, *, field: str) -> str:
    path_text = urlparse(reference).path if reference.startswith("file://") else reference[5:]
    path = Path(path_text).expanduser()
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise SecretError(f"{field} references unreadable secret file: {path}") from exc
    if value == "":
        raise SecretError(f"{field} references empty secret file: {path}")
    return value


def _read_aws_secret(reference: str, *, field: str) -> str:
    secret_id, json_field = _split_reference(reference.removeprefix("aws-sm://"))
    output = _read_command_secret(
        [
            "aws",
            "secretsmanager",
            "get-secret-value",
            "--secret-id",
            secret_id,
            "--query",
            "SecretString",
            "--output",
            "text",
        ],
        provider="AWS Secrets Manager",
        field=field,
    )
    return _select_json_field(output, json_field, field=field) if json_field else output


def _read_vault_secret(reference: str, *, field: str) -> str:
    secret_path, secret_field = _split_reference(reference.removeprefix("vault://"))
    return _read_command_secret(
        ["vault", "kv", "get", f"-field={secret_field or 'value'}", secret_path],
        provider="Vault",
        field=field,
    )


def _read_command_secret(command: list[str], *, provider: str, field: str) -> str:
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
    except FileNotFoundError as exc:
        raise SecretError(f"{field} references {provider}, but its CLI is not installed") from exc
    except subprocess.CalledProcessError as exc:
        raise SecretError(f"{field} could not read secret from {provider}") from exc
    value = result.stdout.strip()
    if value == "":
        raise SecretError(f"{field} read an empty secret from {provider}")
    return value


def _split_reference(reference: str) -> tuple[str, str | None]:
    if "#" not in reference:
        return reference, None
    path, field = reference.rsplit("#", 1)
    return path, field or None


def _select_json_field(value: str, json_field: str | None, *, field: str) -> str:
    if not json_field:
        return value
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as exc:
        raise SecretError(f"{field} expected JSON secret material for #{json_field}") from exc
    selected = payload.get(json_field) if isinstance(payload, dict) else None
    if selected is None:
        raise SecretError(f"{field} could not find #{json_field} in secret material")
    return str(selected)
