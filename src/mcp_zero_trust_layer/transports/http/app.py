from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse, Response
from starlette.middleware.trustedhost import TrustedHostMiddleware

from mcp_zero_trust_layer.config import load_config
from mcp_zero_trust_layer.config.models import MCPZTConfig
from mcp_zero_trust_layer.core.pipeline import MCPPipeline
from mcp_zero_trust_layer.identity import AuthError, AuthResolver
from mcp_zero_trust_layer.observability import MetricsCollector
from mcp_zero_trust_layer.protocol import error_response
from mcp_zero_trust_layer.upstream.http import HTTPUpstreamClient


def create_http_app(config_path: str | Path, default_server: str | None = None) -> FastAPI:
    config = load_config(config_path)
    return create_app_from_config(config, default_server=default_server)


def create_app_from_config(config: MCPZTConfig, default_server: str | None = None) -> FastAPI:
    docs_enabled = config.project.environment != "production"
    app = FastAPI(
        title="MCP Zero Trust Layer",
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )
    if config.runtime.trusted_hosts:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=config.runtime.trusted_hosts)
    metrics = MetricsCollector() if config.metrics.enabled else None
    pipeline = MCPPipeline(config, HTTPUpstreamClient(), metrics=metrics)
    auth = AuthResolver(config.auth)
    selected_default_server = default_server or _default_server_name(config)

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {"status": "ok", "project": config.project.name}

    if metrics is not None:

        @app.get(config.metrics.path)
        def prometheus_metrics() -> Response:
            return Response(metrics.render_prometheus(), media_type="text/plain; version=0.0.4")

    @app.get("/.well-known/oauth-protected-resource")
    def protected_resource_metadata_root(request: Request) -> dict[str, Any]:
        return _protected_resource_metadata(config, _mcp_resource_url(config, request))

    @app.get("/.well-known/oauth-protected-resource/mcp")
    def protected_resource_metadata_mcp(request: Request) -> dict[str, Any]:
        return _protected_resource_metadata(config, _mcp_resource_url(config, request))

    @app.get("/mcp")
    def get_mcp() -> Response:
        return Response(status_code=405)

    @app.post("/mcp")
    async def post_mcp(
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
        x_mcpzt_subject: Annotated[str | None, Header()] = None,
        x_mcpzt_client_id: Annotated[str | None, Header()] = None,
        x_mcpzt_agent_id: Annotated[str | None, Header()] = None,
    ) -> Response:
        return await _handle_post(
            request,
            pipeline,
            auth,
            selected_default_server,
            config,
            authorization=authorization,
            x_mcpzt_subject=x_mcpzt_subject,
            x_mcpzt_client_id=x_mcpzt_client_id,
            x_mcpzt_agent_id=x_mcpzt_agent_id,
        )

    @app.post("/mcp/{server_name}")
    async def post_mcp_server(
        server_name: str,
        request: Request,
        authorization: Annotated[str | None, Header()] = None,
        x_mcpzt_subject: Annotated[str | None, Header()] = None,
        x_mcpzt_client_id: Annotated[str | None, Header()] = None,
        x_mcpzt_agent_id: Annotated[str | None, Header()] = None,
    ) -> Response:
        return await _handle_post(
            request,
            pipeline,
            auth,
            server_name,
            config,
            authorization=authorization,
            x_mcpzt_subject=x_mcpzt_subject,
            x_mcpzt_client_id=x_mcpzt_client_id,
            x_mcpzt_agent_id=x_mcpzt_agent_id,
        )

    return app


async def _handle_post(
    request: Request,
    pipeline: MCPPipeline,
    auth: AuthResolver,
    server_name: str,
    config: MCPZTConfig,
    *,
    authorization: str | None,
    x_mcpzt_subject: str | None,
    x_mcpzt_client_id: str | None,
    x_mcpzt_agent_id: str | None,
) -> Response:
    origin_error = _origin_error(config, request.headers.get("origin"))
    if origin_error:
        return JSONResponse(error_response(None, -32041, origin_error), status_code=403)

    try:
        payload = await _read_bounded_json(request, config.runtime.max_request_bytes)
    except PayloadTooLargeError:
        return JSONResponse(error_response(None, -32042, "Request body too large"), status_code=413)
    except ValueError:
        return JSONResponse(error_response(None, -32700, "Parse error"), status_code=400)
    if not isinstance(payload, dict):
        return JSONResponse(error_response(None, -32600, "Invalid Request"), status_code=400)

    headers = dict(request.headers.items())
    if authorization is not None:
        headers["authorization"] = authorization
    if x_mcpzt_subject is not None:
        headers["x-mcpzt-subject"] = x_mcpzt_subject
    if x_mcpzt_client_id is not None:
        headers["x-mcpzt-client-id"] = x_mcpzt_client_id
    if x_mcpzt_agent_id is not None:
        headers["x-mcpzt-agent-id"] = x_mcpzt_agent_id
    try:
        identity = auth.resolve_http_identity(
            headers=headers,
            source_ip=request.client.host if request.client else None,
            fallback_subject="http-client",
            environment=config.project.environment,
        )
    except AuthError as exc:
        response = JSONResponse(
            error_response(payload.get("id"), -32040, exc.message),
            status_code=401,
        )
        response.headers["WWW-Authenticate"] = _www_authenticate_header(config, request)
        return response

    response = pipeline.handle(
        server_name,
        payload,
        identity=identity,
        headers=headers,
    )
    if response is None:
        return Response(status_code=202)
    return JSONResponse(response)


def _default_server_name(config: MCPZTConfig) -> str:
    http_servers = [server for server in config.servers if server.transport == "http"]
    if not http_servers:
        return config.servers[0].name
    return http_servers[0].name


def _origin_error(config: MCPZTConfig, origin: str | None) -> str | None:
    allowed = config.runtime.allowed_origins
    if not allowed or not origin:
        return None
    if origin not in allowed:
        return "invalid Origin header"
    return None


def _protected_resource_metadata(config: MCPZTConfig, resource: str) -> dict[str, Any]:
    authorization_servers = config.auth.authorization_servers[:]
    if config.auth.issuer and config.auth.issuer not in authorization_servers:
        authorization_servers.append(config.auth.issuer)
    metadata: dict[str, Any] = {"resource": resource}
    if authorization_servers:
        metadata["authorization_servers"] = authorization_servers
    if config.auth.required_scopes:
        metadata["scopes_supported"] = config.auth.required_scopes
    return metadata


def _www_authenticate_header(config: MCPZTConfig, request: Request) -> str:
    base = _public_base_url(config, request)
    metadata_url = f"{base}/.well-known/oauth-protected-resource/mcp"
    pieces = [f'Bearer resource_metadata="{metadata_url}"']
    if config.auth.required_scopes:
        pieces.append(f'scope="{" ".join(config.auth.required_scopes)}"')
    return ", ".join(pieces)


def _mcp_resource_url(config: MCPZTConfig, request: Request) -> str:
    return f"{_public_base_url(config, request)}/mcp"


def _public_base_url(config: MCPZTConfig, request: Request) -> str:
    if config.runtime.public_base_url:
        return config.runtime.public_base_url.rstrip("/")
    return str(request.base_url).rstrip("/")


class PayloadTooLargeError(Exception):
    pass


async def _read_bounded_json(request: Request, max_bytes: int) -> Any:
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            declared_length = int(content_length)
        except ValueError as exc:
            raise ValueError("invalid content-length") from exc
        if declared_length > max_bytes:
            raise PayloadTooLargeError

    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > max_bytes:
            raise PayloadTooLargeError
        chunks.append(chunk)
    return json.loads(b"".join(chunks))
