from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any

import typer

from mcp_zero_trust_layer.config import load_config
from mcp_zero_trust_layer.evidence.canonical import MAX_BYTES, canonical, loads
from mcp_zero_trust_layer.evidence.check_models import (
    CheckedBundle,
    ObserverTrust,
    StripeCheckConfig,
)
from mcp_zero_trust_layer.evidence.demo import run_demo
from mcp_zero_trust_layer.evidence.models import TrustStore, bundle_schema
from mcp_zero_trust_layer.evidence.runtime import EvidenceRuntime
from mcp_zero_trust_layer.evidence.verify import verify_bundle

app = typer.Typer(help="Experimental destination evidence (local operator commands)")


def read_json(path: Path) -> Any:
    with path.open("rb") as handle:
        return loads(handle.read(MAX_BYTES + 1))


@app.command("verify")
def verify(bundle: Path = typer.Argument(...), trust: Path = typer.Option(...),
           request: Path | None = typer.Option(None), response: Path | None = typer.Option(None),
           observers: Path | None = typer.Option(None)) -> None:
    """Verify offline against independently supplied trust; optional canonical preimages."""
    try:
        verdict = verify_bundle(read_json(bundle), TrustStore.model_validate(read_json(trust)),
                                request=read_json(request) if request else None,
                                response=read_json(response) if response else None,
                                observers=ObserverTrust.model_validate(read_json(observers))
                                if observers else None)
    except (ValueError, OSError):
        typer.echo(json.dumps({"rejection": "INVALID_INPUT"}))
        raise typer.Exit(2) from None
    typer.echo(json.dumps(verdict))
    if verdict["rejection"]:
        raise typer.Exit(1)


def runtime(config: Path, server: str) -> EvidenceRuntime:
    cfg = load_config(config)
    target = next((s for s in cfg.servers if s.name == server), None)
    if target is None or target.evidence.mode == "off":
        raise ValueError("evidence server not configured")
    return EvidenceRuntime(target.evidence, cfg.config_base_dir)


@app.command("show")
def show(operation: str, config: Path = typer.Option(...), server: str = typer.Option(...),
         observers: Path | None = typer.Option(None)) -> None:
    """Read local operation status; filesystem/config access is operator authority."""
    try:
        service = runtime(config, server)
        bundle = service.store.checked_bundle(operation, service.config.tenant)
        typer.echo(json.dumps({"operation_id": operation,
            "verdict": verify_bundle(bundle, service.trust,
                observers=ObserverTrust.model_validate(read_json(observers)) if observers else None),
            "events": service.store.events(operation, service.config.tenant)}))
    except (ValueError, OSError):
        raise typer.BadParameter("Unable to read evidence for this configured tenant") from None


@app.command("export")
def export(operation: str, output: Path = typer.Option(...), config: Path = typer.Option(...),
           server: str = typer.Option(...), version: int = typer.Option(2, min=1, max=2)) -> None:
    """Export commitments only, with private permissions; never overwrite files."""
    try:
        service = runtime(config, server)
        bundle = (service.store.checked_bundle(operation, service.config.tenant) if version == 2
                  else service.store.get(operation, service.config.tenant))
        encoded = canonical(bundle).decode()
        with os.fdopen(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as handle:
            handle.write(encoded)
    except (ValueError, OSError):
        raise typer.BadParameter("Unable to export evidence; output must be a new file") from None


@app.command("reconcile")
def reconcile(operation: str, config: Path = typer.Option(...), server: str = typer.Option(...)) -> None:
    """Query the configured destination, NEVER resend the business operation."""
    from mcp_zero_trust_layer.protocol import JSONRPCError
    from mcp_zero_trust_layer.upstream.http import HTTPUpstreamClient
    from mcp_zero_trust_layer.upstream.stdio import StdioProcessUpstream

    try:
        service = runtime(config, server)
        target = next(s for s in load_config(config).servers if s.name == server)
        peer = StdioProcessUpstream(target) if target.transport == "stdio" else HTTPUpstreamClient()
        try:
            result = service.reconcile(operation, lambda message: peer.send(target, message))
            typer.echo(json.dumps(result))
        finally:
            if isinstance(peer, StdioProcessUpstream):
                peer.close()
    except (ValueError, OSError, JSONRPCError):
        raise typer.BadParameter("Reconciliation unavailable; execution outcome may be unknown") from None


@app.command("schema")
def schema(version: int = typer.Option(1, min=1, max=2)) -> None:
    """Emit the versioned bundle envelope JSON Schema."""
    if version == 1:
        result = bundle_schema()
    else:
        result = CheckedBundle.model_json_schema()
        # Reuse v1's payload constraints inside the v2 envelope.
        result["$defs"].update(bundle_schema()["$defs"])
    typer.echo(json.dumps(result, indent=2))


@app.command("check")
def check(operation: str, config: Path = typer.Option(...), server: str = typer.Option(...),
          checker: Path = typer.Option(...), request: Path = typer.Option(...)) -> None:
    """Read Stripe TEST state, append an observer attestation; NEVER execute/refund."""
    from mcp_zero_trust_layer.evidence.checks import (
        StripeRefundReader,
        check_refund,
        load_observer_private_key,
        observation_digest,
    )

    try:
        service = runtime(config, server)
        settings = StripeCheckConfig.model_validate(read_json(checker))
        root = checker.resolve().parent
        trust = ObserverTrust.model_validate(read_json(root / settings.observer_trust_file))
        key = load_observer_private_key(root / settings.observer_private_key_file)
        current = CheckedBundle.model_validate(service.store.checked_bundle(
            operation, service.config.tenant))
        if len(current.observations) >= 256 or verify_bundle(
                current.model_dump(), service.trust, observers=trust)["rejection"]:
            raise ValueError("EXISTING_CHECK_HISTORY_INVALID_OR_FULL")
        reader = StripeRefundReader(os.environ.get(settings.api_key_env, ""), settings.account)
        try:
            record = check_refund(current.evidence.model_dump(), read_json(request), service.trust,
                settings, trust, key, reader,
                previous=observation_digest(current.observations[-1]) if current.observations else None)
        finally:
            reader.close()
        service.store.append_observation(operation, service.config.tenant, record.model_dump())
    except (ValueError, OSError, sqlite3.Error):
        typer.echo(json.dumps({"rejection": "CHECK_UNAVAILABLE", "effect": "unknown"}))
        raise typer.Exit(2) from None
    typer.echo(json.dumps({"check_id": record.payload.check_id,
        "external_check": {"result": record.payload.result, "reason": record.payload.reason,
            "basis": "online_provider_query", "scope": record.payload.scope,
            "provider_signature": "not_provided", "independence": "not_proven"},
        "destination_effect": "committed", "destination_effect_basis": "destination_attested"}))
    if record.payload.result != "corroborated":
        raise typer.Exit(1)


@app.command("demo")
def demo(directory: Path = typer.Option(...)) -> None:
    """Run a real stdio destination and verify one allowed and one denied refund."""
    try:
        typer.echo(json.dumps(run_demo(directory), indent=2))
    except (ValueError, OSError):
        raise typer.BadParameter("Demo failed; use a new directory and inspect local state") from None


@app.command("check-demo")
def check_demo(directory: Path = typer.Option(...)) -> None:
    """Generate adversarial timeout/check fixtures using a SIMULATED provider."""
    from mcp_zero_trust_layer.evidence.check_demo import run_check_demo
    try:
        typer.echo(json.dumps(run_check_demo(directory), indent=2))
    except (ValueError, OSError):
        raise typer.BadParameter("Check demo failed; use a new directory") from None
