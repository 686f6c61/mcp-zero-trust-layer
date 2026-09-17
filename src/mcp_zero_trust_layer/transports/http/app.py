from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool
from starlette.middleware.trustedhost import TrustedHostMiddleware

from mcp_zero_trust_layer.config import load_config
from mcp_zero_trust_layer.config.models import MCPZTConfig
from mcp_zero_trust_layer.core.pipeline import MCPPipeline
from mcp_zero_trust_layer.identity import AuthError, AuthResolver
from mcp_zero_trust_layer.observability import MetricsCollector
from mcp_zero_trust_layer.protocol import error_response
from mcp_zero_trust_layer.protocol.jsonrpc import strict_json_loads
from mcp_zero_trust_layer.transports.http.sessions import SessionRegistry
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
    upstream = HTTPUpstreamClient()
    pipeline = MCPPipeline(config, upstream, metrics=metrics)
    sessions = SessionRegistry(upstream)
    app.state.sessions = sessions
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
            sessions=sessions,
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
            sessions=sessions,
            authorization=authorization,
            x_mcpzt_subject=x_mcpzt_subject,
            x_mcpzt_client_id=x_mcpzt_client_id,
            x_mcpzt_agent_id=x_mcpzt_agent_id,
        )

    @app.delete("/mcp")
    @app.delete("/mcp/{server_name}")
    async def delete_session(request: Request, server_name: str = selected_default_server) -> Response:
        if _origin_error(config, request.headers.get("origin")):
            return Response(status_code=403)
        try:
            identity = auth.resolve_http_identity(
                headers=dict(request.headers), source_ip=request.client.host if request.client else None,
                fallback_subject="http-client", environment=config.project.environment,
            )
        except AuthError:
            return Response(status_code=401, headers={"WWW-Authenticate": _www_authenticate_header(config, request)})
        supplied = request.headers.get("mcp-session-id")
        if not supplied:
            return Response(status_code=400)
        try:
            key = sessions.resolve(server_name, identity, supplied, initialize=False)
        except KeyError:
            return Response(status_code=404)
        if key:
            sessions.remove(key)
        return Response(status_code=204)

    return app


async def _handle_post(
    request: Request,
    pipeline: MCPPipeline,
    auth: AuthResolver,
    server_name: str,
    config: MCPZTConfig,
    *,
    sessions: SessionRegistry,
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
        auth_response = JSONResponse(
            error_response(payload.get("id"), -32040, exc.message),
            status_code=401,
        )
        auth_response.headers["WWW-Authenticate"] = _www_authenticate_header(config, request)
        return auth_response

    protocol_version = request.headers.get("mcp-protocol-version")
    if protocol_version and protocol_version not in {"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"}:
        return JSONResponse(error_response(payload.get("id"), -32600, "Unsupported MCP protocol version"), status_code=400)
    initialize = payload.get("method") == "initialize"
    try:
        session_key = sessions.resolve(server_name, identity, request.headers.get("mcp-session-id"), initialize=initialize)
    except KeyError:
        return JSONResponse(error_response(payload.get("id"), -32044, "Unknown session"), status_code=404)
    except ValueError as exc:
        return JSONResponse(error_response(payload.get("id"), -32600, str(exc)), status_code=400)
    except OverflowError:
        return JSONResponse(error_response(payload.get("id"), -32044, "Session capacity reached"), status_code=503)
    # Never trust caller-provided internal routing keys.
    headers.pop("x-mcpzt-session-key", None)
    headers.pop("mcp-session-id", None)
    if session_key:
        headers["x-mcpzt-session-key"] = session_key

    # pipeline.handle performs blocking upstream I/O; offload it so a slow
    # upstream cannot stall the whole event loop.
    try:
        handled: dict[str, Any] | None = await run_in_threadpool(
            pipeline.handle, server_name, payload, identity=identity, headers=headers,
        )
    except Exception:
        if initialize and session_key:
            sessions.remove(session_key)
        raise
    if session_key and not sessions.active(session_key):
        return JSONResponse(error_response(payload.get("id"), -32044, "Session expired"), status_code=404)
    upstream_error = handled.get("error", {}) if handled else {}
    upstream_error_data = upstream_error.get("data")
    if session_key and upstream_error.get("code") == -32003 and isinstance(upstream_error_data, dict) and upstream_error_data.get("status_code") == 404:
        sessions.remove(session_key)
        return JSONResponse(handled, status_code=404)
    if initialize and session_key and (handled is None or "error" in handled):
        sessions.remove(session_key)
        session_key = None
    response = Response(status_code=202) if handled is None else JSONResponse(handled)
    if session_key:
        response.headers["Mcp-Session-Id"] = session_key
    return response


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
    return strict_json_loads(b"".join(chunks))
