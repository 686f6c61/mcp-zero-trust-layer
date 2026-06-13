# Security Policy

MCP Zero Trust Layer is security-sensitive infrastructure. Please do not open public issues for suspected vulnerabilities until they have been triaged.

## Supported Versions

The project is currently in the `0.x` line. Security fixes are applied to the latest released `0.x` version unless a maintainer announces a different support window.

## Reporting A Vulnerability

Preferred path:

1. Use GitHub private vulnerability reporting or a GitHub Security Advisory for the repository.
2. Include affected version, configuration shape, transport mode, reproduction steps, impact, and any relevant logs with secrets removed.
3. Do not include live credentials, tokens, private prompts, production audit logs, or customer data.

Expected triage:

- Critical: authentication bypass, policy bypass, secret exposure, arbitrary command execution.
- High: approval bypass, audit redaction failure, upstream header leakage, production fail-open behavior.
- Medium: denial of service, confusing policy behavior, unsafe default in non-production.
- Low: documentation ambiguity, non-sensitive information disclosure, hardening improvement.

## Security Design Commitments

- Production defaults fail closed.
- Stdio mode keeps stdout protocol-only.
- Audit redaction happens before writing.
- Policy enforcement happens before upstream execution.
- Denied calls must not reach upstream.
- Approval retries are bound to identity, capability, policy and argument hash.
- HTTP upstream forwarding uses an explicit header allowlist.

## Out Of Scope

MCP Zero Trust Layer reduces risk around MCP capability exposure, but it does not guarantee complete protection from prompt injection, compromised upstream servers, compromised identity providers, malicious local users, or insecure deployment networks.
