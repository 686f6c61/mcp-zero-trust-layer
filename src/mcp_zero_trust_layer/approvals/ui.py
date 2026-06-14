from __future__ import annotations

import html
import json
from typing import Any
from urllib.parse import parse_qs

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from mcp_zero_trust_layer.approvals.store import ApprovalStore
from mcp_zero_trust_layer.config.models import MCPZTConfig

APPROVAL_NOT_FOUND_RESPONSE = {404: {"description": "Approval not found"}}


def create_approvals_app(config: MCPZTConfig) -> FastAPI:
    app = FastAPI(
        title="MCPZT Approvals",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    store = ApprovalStore(config.approvals)

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        return HTMLResponse(_render_index(store.list(), config.project.name))

    @app.get("/api/approvals")
    def list_approvals() -> JSONResponse:
        return JSONResponse([approval.model_dump(mode="json") for approval in store.list()])

    @app.post("/api/approvals/{approval_id}/allow", responses=APPROVAL_NOT_FOUND_RESPONSE)
    async def api_allow(approval_id: str, request: Request) -> JSONResponse:
        approval = _set_status_from_request(store, approval_id, "approved", await _payload(request))
        return JSONResponse(approval.model_dump(mode="json"))

    @app.post("/api/approvals/{approval_id}/deny", responses=APPROVAL_NOT_FOUND_RESPONSE)
    async def api_deny(approval_id: str, request: Request) -> JSONResponse:
        approval = _set_status_from_request(store, approval_id, "denied", await _payload(request))
        return JSONResponse(approval.model_dump(mode="json"))

    @app.post("/approvals/{approval_id}/allow", responses=APPROVAL_NOT_FOUND_RESPONSE)
    async def web_allow(approval_id: str, request: Request) -> RedirectResponse:
        _set_status_from_request(store, approval_id, "approved", await _payload(request))
        return RedirectResponse("/", status_code=303)

    @app.post("/approvals/{approval_id}/deny", responses=APPROVAL_NOT_FOUND_RESPONSE)
    async def web_deny(approval_id: str, request: Request) -> RedirectResponse:
        _set_status_from_request(store, approval_id, "denied", await _payload(request))
        return RedirectResponse("/", status_code=303)

    return app


async def _payload(request: Request) -> dict[str, Any]:
    content_type = request.headers.get("content-type", "")
    body = await request.body()
    if not body:
        return {}
    if "application/json" in content_type:
        parsed = json.loads(body)
        return parsed if isinstance(parsed, dict) else {}
    fields = parse_qs(body.decode("utf-8"), keep_blank_values=True)
    return {key: values[-1] for key, values in fields.items() if values}


def _set_status_from_request(
    store: ApprovalStore,
    approval_id: str,
    status: str,
    payload: dict[str, Any],
) -> Any:
    try:
        return store.set_status(
            approval_id,
            status,  # type: ignore[arg-type]
            decided_by=str(payload.get("decided_by") or payload.get("by") or "approval-ui"),
            decision_comment=_optional_str(payload.get("comment")),
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="approval not found") from exc


def _render_index(approvals: list[Any], project_name: str) -> str:
    cards = "\n".join(_approval_card(approval) for approval in approvals)
    if not cards:
        cards = '<section class="empty">No approvals yet.</section>'
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MCPZT Approvals</title>
  <style>
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      color: #17202a;
      background: #f4f7fa;
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
    }}
    main {{ width: min(1180px, calc(100vw - 32px)); margin: 0 auto; padding: 32px 0; }}
    header {{ display: flex; align-items: flex-end; justify-content: space-between; gap: 16px; margin-bottom: 20px; }}
    h1 {{ font-size: 28px; line-height: 1.1; margin: 0 0 6px; letter-spacing: 0; }}
    p {{ margin: 0; color: #536475; }}
    code, pre {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
    .count {{ color: #536475; font-size: 14px; white-space: nowrap; }}
    .approval-list {{ display: grid; gap: 14px; }}
    .approval-card {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) 260px;
      gap: 18px;
      background: #ffffff;
      border: 1px solid #dbe4ed;
      border-radius: 8px;
      padding: 18px;
      box-shadow: 0 1px 2px rgba(23, 32, 42, 0.04);
    }}
    .approval-main {{ min-width: 0; }}
    .approval-top {{ display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; margin-bottom: 14px; }}
    .capability {{ overflow-wrap: anywhere; font-size: 18px; font-weight: 700; line-height: 1.25; }}
    .approval-id {{ display: block; margin-top: 5px; color: #536475; font-size: 12px; overflow-wrap: anywhere; }}
    .status {{
      border-radius: 999px;
      padding: 4px 9px;
      background: #eaf2ff;
      color: #174b8a;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      white-space: nowrap;
    }}
    .status.approved {{ background: #e7f6ed; color: #16623f; }}
    .status.denied {{ background: #fae9e9; color: #8f2727; }}
    .meta {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; margin-bottom: 14px; }}
    .meta-item {{ min-width: 0; }}
    .label {{ color: #6a7a8a; font-size: 12px; line-height: 1.4; }}
    .value {{ color: #17202a; font-size: 14px; line-height: 1.35; overflow-wrap: anywhere; }}
    .arguments {{ margin: 0; max-height: 180px; overflow: auto; border: 1px solid #e2e9f0; border-radius: 6px; background: #f8fafc; padding: 10px; color: #2a3744; font-size: 12px; line-height: 1.45; }}
    .decision {{ border-left: 1px solid #e2e9f0; padding-left: 18px; }}
    .decision-title {{ margin: 0 0 10px; font-weight: 700; }}
    form {{ display: grid; gap: 8px; margin: 0 0 12px; }}
    input {{ width: 100%; min-width: 0; border: 1px solid #bdc9d5; border-radius: 6px; padding: 8px 9px; font: inherit; }}
    .actions {{ display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }}
    button {{ border: 1px solid #91a4b7; background: #ffffff; color: #17202a; padding: 8px 10px; border-radius: 6px; cursor: pointer; font-weight: 700; }}
    button.allow {{ border-color: #1f7a4d; color: #11623a; }}
    button.deny {{ border-color: #a23b3b; color: #8a2424; }}
    button:disabled, input:disabled {{ cursor: not-allowed; opacity: 0.55; }}
    .decision-note {{ color: #536475; font-size: 13px; line-height: 1.4; }}
    .empty {{ text-align: center; color: #66788a; padding: 28px; background: #ffffff; border: 1px solid #dbe4ed; border-radius: 8px; }}
    @media (max-width: 840px) {{
      main {{ width: min(100vw - 20px, 720px); padding: 20px 0; }}
      header, .approval-top {{ display: grid; }}
      .approval-card {{ grid-template-columns: 1fr; }}
      .decision {{ border-left: 0; border-top: 1px solid #e2e9f0; padding-left: 0; padding-top: 14px; }}
      .meta {{ grid-template-columns: 1fr; }}
      .count {{ white-space: normal; }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <div>
        <h1>MCPZT Approvals</h1>
        <p>{html.escape(project_name)}</p>
      </div>
      <div class="count">{len(approvals)} total</div>
    </header>
    <section class="approval-list">{cards}</section>
  </main>
</body>
</html>"""


def _approval_card(approval: Any) -> str:
    disabled = " disabled" if approval.status != "pending" else ""
    status_class = html.escape(str(approval.status))
    arguments = _approval_arguments(approval)
    decision_note = _decision_note(approval)
    return f"""<article class="approval-card">
  <div class="approval-main">
    <div class="approval-top">
      <div>
        <div class="capability">{html.escape(approval.capability or approval.capability_type)}</div>
        <code class="approval-id">{html.escape(approval.id)}</code>
      </div>
      <div class="status {status_class}">{html.escape(approval.status)}</div>
    </div>
    <div class="meta">
      {_meta_item("Server", approval.server)}
      {_meta_item("Policy", approval.policy_id)}
      {_meta_item("Subject", approval.identity_subject)}
      {_meta_item("Client", getattr(approval, "client_id", None) or "-")}
      {_meta_item("Agent", getattr(approval, "agent_id", None) or "-")}
      {_meta_item("Expires", approval.expires_at.isoformat() if approval.expires_at else "-")}
    </div>
    <pre class="arguments">{arguments}</pre>
  </div>
  <aside class="decision">
    <p class="decision-title">Decision</p>
    <form method="post" action="/approvals/{html.escape(approval.id)}/allow">
      <input name="decided_by" placeholder="approver"{disabled}>
      <div class="actions">
        <button class="allow" type="submit"{disabled}>Allow</button>
        <button class="deny" type="submit" formaction="/approvals/{html.escape(approval.id)}/deny"{disabled}>Deny</button>
      </div>
    </form>
    {decision_note}
  </aside>
</article>"""


def _meta_item(label: str, value: Any) -> str:
    return f"""<div class="meta-item">
  <div class="label">{html.escape(label)}</div>
  <div class="value">{html.escape(str(value))}</div>
</div>"""


def _approval_arguments(approval: Any) -> str:
    payload = getattr(approval, "arguments_redacted", {}) or {}
    return html.escape(json.dumps(payload, indent=2, sort_keys=True))


def _decision_note(approval: Any) -> str:
    if approval.status == "pending":
        return ""
    decided_by = html.escape(str(approval.decided_by or "approval-ui"))
    decided_at = html.escape(approval.decided_at.isoformat() if approval.decided_at else "")
    return f'<div class="decision-note">Decided by {decided_by}<br>{decided_at}</div>'


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    value = str(value)
    return value or None
