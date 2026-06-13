from __future__ import annotations

import ipaddress
import re
import socket
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from mcp_zero_trust_layer.validators.models import ValidatorResult

FORBIDDEN_SQL_RE = re.compile(
    r"\b(DROP|DELETE|UPDATE|INSERT|ALTER|TRUNCATE|CREATE|GRANT|REVOKE|MERGE|CALL|EXEC)\b",
    re.IGNORECASE,
)


def validate_sql_read_only(arguments: dict[str, Any], options: dict[str, Any]) -> ValidatorResult:
    query_arg = options.get("query_arg")
    query = _first_value(arguments, [query_arg, "query", "sql", "statement"])
    if not isinstance(query, str) or not query.strip():
        return ValidatorResult.fail("sql_read_only could not find a SQL string")

    normalized = _strip_sql_comments(query).strip()
    if FORBIDDEN_SQL_RE.search(normalized):
        return ValidatorResult.fail("sql_read_only blocked a destructive SQL keyword")
    if not re.match(r"^(SELECT|WITH|EXPLAIN)\b", normalized, flags=re.IGNORECASE):
        return ValidatorResult.fail("sql_read_only only allows SELECT, WITH, or EXPLAIN statements")
    return ValidatorResult.ok()


def validate_filesystem_path(arguments: dict[str, Any], options: dict[str, Any]) -> ValidatorResult:
    path_arg = options.get("path_arg", "path")
    raw_path = arguments.get(path_arg)
    if not isinstance(raw_path, str) or not raw_path:
        return ValidatorResult.fail(f"filesystem_path could not find path argument {path_arg!r}")

    base_dir = _base_dir(options)
    candidate = _path_relative_to_base(raw_path, base_dir)
    resolved = candidate.expanduser().resolve(strict=False)
    allowed_roots = options.get("allowed_roots", [])
    if allowed_roots:
        root_paths = [
            _path_relative_to_base(str(root), base_dir).expanduser().resolve(strict=False)
            for root in allowed_roots
        ]
        if not any(_is_relative_to(resolved, root) for root in root_paths):
            return ValidatorResult.fail("filesystem_path blocked path outside allowed_roots")

    for sensitive in options.get("blocked_paths", ["/etc", "/var/run", "/private/etc"]):
        sensitive_path = (
            _path_relative_to_base(str(sensitive), base_dir).expanduser().resolve(strict=False)
        )
        if _is_relative_to(resolved, sensitive_path):
            return ValidatorResult.fail("filesystem_path blocked sensitive path")

    if options.get("read_only", False):
        operation = str(arguments.get("operation", "read")).lower()
        if operation not in {"read", "list", "stat"}:
            return ValidatorResult.fail("filesystem_path blocked non-read operation")

    return ValidatorResult.ok()


def validate_url(arguments: dict[str, Any], options: dict[str, Any]) -> ValidatorResult:
    url_arg = options.get("url_arg", "url")
    raw_url = arguments.get(url_arg)
    if not isinstance(raw_url, str) or not raw_url:
        return ValidatorResult.fail(f"url validator could not find URL argument {url_arg!r}")

    parsed = urlparse(raw_url)
    allowed_schemes = set(options.get("allowed_schemes", ["http", "https"]))
    if parsed.scheme not in allowed_schemes:
        return ValidatorResult.fail("url validator blocked disallowed scheme")
    if not parsed.hostname:
        return ValidatorResult.fail("url validator requires hostname")

    host = parsed.hostname.lower()
    if host in set(options.get("blocked_domains", [])):
        return ValidatorResult.fail("url validator blocked domain")
    allowed_domains = set(options.get("allowed_domains", []))
    if allowed_domains and not any(host == domain or host.endswith(f".{domain}") for domain in allowed_domains):
        return ValidatorResult.fail("url validator blocked domain outside allowed_domains")
    if options.get("block_localhost", True) and host in {"localhost", "127.0.0.1", "::1"}:
        return ValidatorResult.fail("url validator blocked localhost")
    if options.get("block_private_ips", True) and _is_private_ip(host):
        return ValidatorResult.fail("url validator blocked private IP")
    if _is_cloud_metadata_host(host):
        return ValidatorResult.fail("url validator blocked cloud metadata service")
    if options.get("block_private_ips", True) and options.get("resolve_dns", True):
        resolved = _resolve_host_ips(host)
        if resolved is None:
            if options.get("allow_unresolved", False):
                return ValidatorResult.ok()
            return ValidatorResult.fail("url validator could not resolve hostname")
        if any(_is_private_ip(ip) or _is_cloud_metadata_host(ip) for ip in resolved):
            return ValidatorResult.fail("url validator blocked hostname resolving to private IP")

    return ValidatorResult.ok()


def validate_email(arguments: dict[str, Any], options: dict[str, Any]) -> ValidatorResult:
    recipients_arg = options.get("recipients_arg", "to")
    raw_recipients = arguments.get(recipients_arg, [])
    if isinstance(raw_recipients, str):
        recipients = [raw_recipients]
    elif isinstance(raw_recipients, list):
        recipients = raw_recipients
    else:
        return ValidatorResult.fail("email validator could not read recipients")

    allowed_domains = set(options.get("allowed_domains", []))
    blocked_domains = set(options.get("blocked_domains", []))
    for recipient in recipients:
        if not isinstance(recipient, str) or "@" not in recipient:
            return ValidatorResult.fail("email validator found invalid recipient")
        domain = recipient.rsplit("@", 1)[1].lower()
        if domain in blocked_domains:
            return ValidatorResult.fail("email validator blocked recipient domain")
        if allowed_domains and domain not in allowed_domains:
            return ValidatorResult.fail("email validator blocked recipient outside allowed_domains")

    if options.get("block_attachments", False) and arguments.get("attachments"):
        return ValidatorResult.fail("email validator blocked attachments")

    return ValidatorResult.ok()


def validate_regex(arguments: dict[str, Any], options: dict[str, Any]) -> ValidatorResult:
    field = options.get("field")
    if not field:
        return ValidatorResult.fail("regex validator requires field option")
    value = str(_get_path(arguments, field) or "")

    allow = options.get("allow")
    if allow and not re.search(allow, value):
        return ValidatorResult.fail("regex validator did not match allow pattern")

    deny = options.get("deny")
    if deny and re.search(deny, value):
        return ValidatorResult.fail("regex validator matched deny pattern")

    return ValidatorResult.ok()


def validate_required_forbidden_fields(
    arguments: dict[str, Any], options: dict[str, Any]
) -> ValidatorResult:
    for field in options.get("required", []):
        if _get_path(arguments, field) is None:
            return ValidatorResult.fail(f"required field missing: {field}")
    for field in options.get("forbidden", []):
        if _get_path(arguments, field) is not None:
            return ValidatorResult.fail(f"forbidden field present: {field}")
    return ValidatorResult.ok()


def validate_max_field_bytes(arguments: dict[str, Any], options: dict[str, Any]) -> ValidatorResult:
    field = options.get("field")
    max_bytes = options.get("max_bytes")
    if not field or not isinstance(max_bytes, int):
        return ValidatorResult.fail("max_field_bytes requires field and integer max_bytes")
    value = _get_path(arguments, field)
    if len(str(value or "").encode("utf-8")) > max_bytes:
        return ValidatorResult.fail(f"field exceeds max_bytes: {field}")
    return ValidatorResult.ok()


def _first_value(arguments: dict[str, Any], keys: list[str | None]) -> Any:
    for key in keys:
        if key and key in arguments:
            return arguments[key]
    return None


def _strip_sql_comments(query: str) -> str:
    without_line_comments = re.sub(r"--.*?$", "", query, flags=re.MULTILINE)
    return re.sub(r"/\*.*?\*/", "", without_line_comments, flags=re.DOTALL)


def _is_relative_to(candidate: Path, root: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def _is_private_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def _resolve_host_ips(host: str) -> list[str] | None:
    try:
        return sorted({item[4][0] for item in socket.getaddrinfo(host, None)})
    except socket.gaierror:
        return None


def _is_cloud_metadata_host(host: str) -> bool:
    return host in {"169.254.169.254", "metadata.google.internal"}


def _base_dir(options: dict[str, Any]) -> Path | None:
    raw = options.get("base_dir")
    if not raw:
        return None
    return Path(str(raw)).expanduser().resolve(strict=False)


def _path_relative_to_base(path: str, base_dir: Path | None) -> Path:
    candidate = Path(path)
    if candidate.is_absolute() or base_dir is None:
        return candidate
    return base_dir / candidate


def _get_path(data: dict[str, Any], path: str) -> Any:
    current: Any = data
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
        if current is None:
            return None
    return current
