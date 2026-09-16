from __future__ import annotations

import ipaddress
import os
import re
import socket
from email.headerregistry import Address
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from mcp_zero_trust_layer.validators.models import ValidatorResult

FORBIDDEN_SQL_RE = re.compile(
    r"\b("
    r"DROP|DELETE|UPDATE|INSERT|ALTER|TRUNCATE|CREATE|GRANT|REVOKE|MERGE|CALL|EXEC|EXECUTE|"
    r"ATTACH|DETACH|COPY|PRAGMA|VACUUM|REPLACE|LOAD|SET|PREPARE|DEALLOCATE|DO|HANDLER|"
    r"REINDEX|ANALYZE|LOCK|UNLOCK|RENAME|IMPORT|INSTALL|KILL|BEGIN|COMMIT|ROLLBACK|SAVEPOINT|"
    r"INTO|NEXT|FOR"
    r")\b",
    re.IGNORECASE,
)
# Deliberately small portable subset. Database read-only permissions remain required.
SAFE_SQL_FUNCTIONS = {
    "abs", "avg", "ceil", "ceiling", "coalesce", "count", "floor", "length", "lower",
    "ltrim", "max", "min", "nullif", "round", "rtrim", "substr", "substring", "sum",
    "trim", "upper",
}
SQL_PAREN_KEYWORDS = {"select", "as", "in", "exists", "not", "and", "or", "where", "on", "having"}
SQL_FUNCTION_RE = re.compile(r'((?:[\w"$]+\s*\.\s*)*[\w"$]+)\s*\(', re.UNICODE)
CLOUD_METADATA_HOSTS = {
    str(ipaddress.IPv4Address(0xA9FEA9FE)),
    "metadata.google.internal",
}
DEFAULT_BLOCKED_PATHS = [
    "/etc",
    "/var/run",
    "/private/etc",
    "/proc",
    "/sys",
    "/root",
    "~/.ssh",
    "~/.aws",
    "~/.config",
    "~/.kube",
]
# Carrier-grade NAT range that is not flagged by ipaddress.is_private.
_CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")


def validate_sql_read_only(arguments: dict[str, Any], options: dict[str, Any]) -> ValidatorResult:
    query_arg = options.get("query_arg")
    query = _first_value(arguments, [query_arg, "query", "sql", "statement"])
    if not isinstance(query, str) or not query.strip():
        return ValidatorResult.fail("sql_read_only could not find a SQL string")

    try:
        normalized = _sql_code(query).strip()
    except ValueError as exc:
        return ValidatorResult.fail(f"sql_read_only blocked unsupported SQL: {exc}")
    statements = _split_sql_statements(normalized)
    if len(statements) > 1:
        return ValidatorResult.fail("sql_read_only blocked multiple SQL statements")
    if FORBIDDEN_SQL_RE.search(normalized):
        return ValidatorResult.fail("sql_read_only blocked a destructive SQL keyword")
    if not re.match(r"^(SELECT|WITH|EXPLAIN)\b", normalized, flags=re.IGNORECASE):
        return ValidatorResult.fail("sql_read_only only allows SELECT, WITH, or EXPLAIN statements")
    for match in SQL_FUNCTION_RE.finditer(normalized):
        name = match.group(1).lower()
        if name not in SAFE_SQL_FUNCTIONS | SQL_PAREN_KEYWORDS:
            return ValidatorResult.fail("sql_read_only blocked an unsupported SQL function or syntax")
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

    for sensitive in options.get("blocked_paths", DEFAULT_BLOCKED_PATHS):
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
    parse_error = _url_parse_error(parsed, options)
    if parse_error:
        return ValidatorResult.fail(parse_error)
    host = (parsed.hostname or "").lower()
    host_error = _url_host_error(host, options)
    if host_error:
        return ValidatorResult.fail(host_error)
    dns_error = _url_dns_error(host, options)
    if dns_error:
        return ValidatorResult.fail(dns_error)
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

    allowed_domains = {str(domain).lower() for domain in options.get("allowed_domains", [])}
    blocked_domains = {str(domain).lower() for domain in options.get("blocked_domains", [])}
    for recipient in recipients:
        if not isinstance(recipient, str) or any(char in recipient for char in "\r\n"):
            return ValidatorResult.fail("email validator found invalid recipient")
        try:
            mailbox = Address(addr_spec=recipient)
        except Exception:
            # Treat every parser failure as invalid untrusted input, never a 500.
            return ValidatorResult.fail("email validator found invalid recipient")
        domain = mailbox.domain.lower()
        if not mailbox.username or not domain or mailbox.addr_spec != recipient.strip():
            return ValidatorResult.fail("email validator found invalid recipient")
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
    raw_value = _get_path(arguments, field)
    value = "" if raw_value is MISSING or raw_value is None else str(raw_value)

    allow = options.get("allow")
    try:
        if allow and not re.search(allow, value):
            return ValidatorResult.fail("regex validator did not match allow pattern")

        deny = options.get("deny")
        if deny and re.search(deny, value):
            return ValidatorResult.fail("regex validator matched deny pattern")
    except re.error as exc:
        return ValidatorResult.fail(f"regex validator has an invalid pattern: {exc}")

    return ValidatorResult.ok()


def validate_required_forbidden_fields(
    arguments: dict[str, Any], options: dict[str, Any]
) -> ValidatorResult:
    for field in options.get("required", []):
        if _get_path(arguments, field) is MISSING:
            return ValidatorResult.fail(f"required field missing: {field}")
    for field in options.get("forbidden", []):
        if _get_path(arguments, field) is not MISSING:
            return ValidatorResult.fail(f"forbidden field present: {field}")
    return ValidatorResult.ok()


def validate_max_field_bytes(arguments: dict[str, Any], options: dict[str, Any]) -> ValidatorResult:
    field = options.get("field")
    max_bytes = options.get("max_bytes")
    if not field or not isinstance(max_bytes, int):
        return ValidatorResult.fail("max_field_bytes requires field and integer max_bytes")
    value = _get_path(arguments, field)
    if value is MISSING:
        return ValidatorResult.ok()
    if len(str(value or "").encode("utf-8")) > max_bytes:
        return ValidatorResult.fail(f"field exceeds max_bytes: {field}")
    return ValidatorResult.ok()


def _first_value(arguments: dict[str, Any], keys: list[str | None]) -> Any:
    for key in keys:
        if key and key in arguments:
            return arguments[key]
    return None


def _sql_code(query: str) -> str:
    """Mask strings/comments using one lexer, keeping SQL structure and identifiers.

    ANSI doubled quotes are supported; dialect-dependent escapes are rejected.
    """
    code: list[str] = []
    position = 0
    while position < len(query):
        char = query[position]
        if query.startswith("--", position):
            newline = query.find("\n", position + 2)
            position = len(query) if newline < 0 else newline + 1
            code.append(" ")
        elif query.startswith("/*", position):
            end = query.find("*/", position + 2)
            if end < 0 or query[position + 2 : position + 3] in {"!", "+"}:
                raise ValueError("unterminated or executable comment")
            if "/*" in query[position + 2 : end]:
                raise ValueError("nested comments are not supported")
            code.append(" ")
            position = end + 2
        elif char in "'\"":
            start = position
            position += 1
            while position < len(query):
                if query[position] == "\\":
                    raise ValueError("backslash escapes are not supported")
                if query[position] == char:
                    if query[position : position + 2] == char * 2:
                        position += 2
                        continue
                    position += 1
                    break
                position += 1
            else:
                raise ValueError("unterminated quoted value")
            code.append(" " if char == "'" else query[start:position])
        elif char in "`[]$\\#" or (ord(char) < 32 and not char.isspace()):
            raise ValueError("dialect-dependent quoting or control character")
        else:
            code.append(char)
            position += 1
    return "".join(code)


def _split_sql_statements(query: str) -> list[str]:
    """Split on top-level ``;`` while ignoring separators inside string literals.

    A trailing separator yields a single statement; a separator followed by more
    SQL yields multiple, which the read-only validator rejects (stacked queries).
    """
    statements: list[str] = []
    current: list[str] = []
    quote: str | None = None
    for char in query:
        if quote is not None:
            current.append(char)
            if char == quote:
                quote = None
        elif char in "'\"":
            quote = char
            current.append(char)
        elif char == ";":
            statements.append("".join(current))
            current = []
        else:
            current.append(char)
    statements.append("".join(current))
    return [statement for statement in statements if statement.strip()]


def _is_relative_to(candidate: Path, root: Path) -> bool:
    # os.path.normcase folds case on case-insensitive filesystems (macOS, Windows)
    # so /ETC/passwd is still recognised as being under /etc.
    candidate_norm = Path(os.path.normcase(str(candidate)))
    root_norm = Path(os.path.normcase(str(root)))
    try:
        candidate_norm.relative_to(root_norm)
        return True
    except ValueError:
        return False


def _normalize_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    # Accept decimal/hex/octal integer literals (e.g. 2130706433, 0x7f000001).
    stripped = host.strip("[]")
    try:
        as_int = int(stripped, 0) if stripped.lower().startswith("0x") else int(stripped)
    except ValueError:
        as_int = None
    if as_int is not None and 0 <= as_int <= 0xFFFFFFFF:
        return ipaddress.ip_address(as_int)
    # Dotted forms with octal/hex octets (e.g. 0177.0.0.1).
    parts = stripped.split(".")
    if len(parts) == 4:
        try:
            octets = [int(part, 0) if part.lower().startswith("0x") else int(part, 8 if part.startswith("0") and part != "0" else 10) for part in parts]
        except ValueError:
            return None
        if all(0 <= octet <= 255 for octet in octets):
            return ipaddress.IPv4Address(bytes(octets))
    return None


def _is_private_ip(host: str) -> bool:
    ip = _normalize_ip(host)
    if ip is None:
        return False
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return True
    return ip.version == 4 and ip in _CGNAT_NETWORK


DNS_TIMEOUT_SECONDS = 5.0


def _resolve_host_ips(host: str) -> list[str] | None:
    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(DNS_TIMEOUT_SECONDS)
    try:
        return sorted({str(item[4][0]) for item in socket.getaddrinfo(host, None)})
    except (TimeoutError, socket.gaierror, UnicodeError, OSError):
        return None
    finally:
        socket.setdefaulttimeout(previous)


def _is_cloud_metadata_host(host: str) -> bool:
    return host in CLOUD_METADATA_HOSTS


def _url_parse_error(parsed: Any, options: dict[str, Any]) -> str | None:
    allowed_schemes = set(options.get("allowed_schemes", ["http", "https"]))
    if parsed.scheme not in allowed_schemes:
        return "url validator blocked disallowed scheme"
    if not parsed.hostname:
        return "url validator requires hostname"
    return None


def _url_host_error(host: str, options: dict[str, Any]) -> str | None:
    if host in set(options.get("blocked_domains", [])):
        return "url validator blocked domain"
    allowed_domains = set(options.get("allowed_domains", []))
    if allowed_domains and not any(host == domain or host.endswith(f".{domain}") for domain in allowed_domains):
        return "url validator blocked domain outside allowed_domains"
    if options.get("block_localhost", True) and host in {"localhost", "127.0.0.1", "::1"}:
        return "url validator blocked localhost"
    if options.get("block_private_ips", True) and _is_private_ip(host):
        return "url validator blocked private IP"
    if _is_cloud_metadata_host(host):
        return "url validator blocked cloud metadata service"
    return None


def _url_dns_error(host: str, options: dict[str, Any]) -> str | None:
    if not options.get("block_private_ips", True) or not options.get("resolve_dns", True):
        return None
    resolved = _resolve_host_ips(host)
    if resolved is None:
        return None if options.get("allow_unresolved", False) else "url validator could not resolve hostname"
    if any(_is_private_ip(ip) or _is_cloud_metadata_host(ip) for ip in resolved):
        return "url validator blocked hostname resolving to private IP"
    return None


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


MISSING = object()


def _get_path(data: dict[str, Any], path: str) -> Any:
    current: Any = data
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return MISSING
        current = current[part]
    return current
