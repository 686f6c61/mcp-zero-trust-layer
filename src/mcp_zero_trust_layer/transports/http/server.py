from __future__ import annotations

from pathlib import Path

import uvicorn

from mcp_zero_trust_layer.transports.http.app import create_http_app


def run_http_server(
    config_path: Path,
    *,
    host: str,
    port: int,
    server: str | None = None,
) -> None:
    app = create_http_app(config_path, default_server=server)
    uvicorn.run(
        app,
        host=host,
        port=port,
        reload=False,
        log_level="info",
    )
