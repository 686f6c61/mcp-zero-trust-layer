from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import typer

from mcp_zero_trust_layer.config import load_config
from mcp_zero_trust_layer.evidence.canonical import MAX_BYTES, loads
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
           request: Path | None = typer.Option(None), response: Path | None = typer.Option(None)) -> None:
    """Verify offline against independently supplied trust; optional canonical preimages."""
    try:
        verdict = verify_bundle(read_json(bundle), TrustStore.model_validate(read_json(trust)),
                                request=read_json(request) if request else None,
                                response=read_json(response) if response else None)
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
def show(operation: str, config: Path = typer.Option(...), server: str = typer.Option(...)) -> None:
    """Read local operation status; filesystem/config access is operator authority."""
    try:
        service = runtime(config, server)
        bundle = service.store.get(operation, service.config.tenant)
        typer.echo(json.dumps({"operation_id": operation,
            "verdict": verify_bundle(bundle, service.trust),
            "events": service.store.events(operation, service.config.tenant)}))
    except (ValueError, OSError):
        raise typer.BadParameter("Unable to read evidence for this configured tenant") from None


@app.command("export")
def export(operation: str, output: Path = typer.Option(...), config: Path = typer.Option(...),
           server: str = typer.Option(...)) -> None:
    """Export commitments only, with private permissions; never overwrite files."""
    try:
        service = runtime(config, server)
        bundle = service.store.get(operation, service.config.tenant)
        with os.fdopen(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as handle:
            json.dump(bundle, handle, indent=2)
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
def schema() -> None:
    """Emit the versioned bundle envelope JSON Schema."""
    typer.echo(json.dumps(bundle_schema(), indent=2))


@app.command("demo")
def demo(directory: Path = typer.Option(...)) -> None:
    """Run a real stdio destination and verify one allowed and one denied refund."""
    try:
        typer.echo(json.dumps(run_demo(directory), indent=2))
    except (ValueError, OSError):
        raise typer.BadParameter("Demo failed; use a new directory and inspect local state") from None
