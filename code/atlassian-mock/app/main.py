"""Mock Atlassian Rovo MCP server, with an ID-JAG-redeeming token endpoint.

    POST /mcp           MCP over Streamable HTTP (JSON-RPC 2.0, revision 2025-06-18)
    POST /oauth/token   RFC 7523 jwt-bearer grant with an ID-JAG (see oauth.py)
    GET  /healthz, /admin/requests, /admin/oauth/grants   observability

Design notes:

* Responses are plain application/json, never SSE-framed; GET /mcp is 405,
  matching the WSO2 API Manager gateway, which offers no stream leg either.
* initialize, notifications, ping and tools/list need no token: the gateway
  discovers the tool catalogue anonymously. tools/call needs an access token
  issued by /oauth/token, and the account behind it decides what comes back.
* Tool failures are isError results on a successful JSON-RPC response; only
  protocol faults produce JSON-RPC error objects.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from collections import deque
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from . import oauth
from .config import PROTOCOL_VERSION, SERVER_NAME, SERVER_VERSION, settings
from .tools import TOOLS, InvalidParams, ToolFailure

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s  %(levelname)-7s  %(message)s",
)
log = logging.getLogger("atlassian-mock")


@asynccontextmanager
async def lifespan(_: FastAPI):
    log.info("Mock Atlassian Rovo MCP server: %d tools, MCP %s, POST http://%s:%d/mcp",
             len(TOOLS), PROTOCOL_VERSION, settings.host, settings.port)
    log.info("Redeeming ID-JAGs from %s (aud %s) for client %s",
             settings.idjag_issuer, settings.idjag_audience, settings.oauth_client_id)
    yield


app = FastAPI(title="Mock Atlassian Rovo MCP Server", version=SERVER_VERSION,
              docs_url=None, redoc_url=None, lifespan=lifespan)
app.include_router(oauth.router)

# JSON-RPC error codes
PARSE_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS, INTERNAL_ERROR = (
    -32700, -32600, -32601, -32602, -32603,
)
UNAUTHORIZED = -32001  # implementation-defined range


class RpcError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code, self.message = code, message


def rpc_result(rpc_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rpc_id, "result": result}


def rpc_error(rpc_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}}


def tool_result(payload: Any, *, is_error: bool = False) -> dict[str, Any]:
    text = payload if isinstance(payload, str) else json.dumps(payload, indent=2, ensure_ascii=False)
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


# ---------------------------------------------------------------------------
# Request log: what reached the upstream, for GET /admin/requests
# ---------------------------------------------------------------------------

_requests: deque[dict[str, Any]] = deque(maxlen=200)
_LOGGED_HEADERS = ("content-type", "accept", "mcp-session-id", "mcp-protocol-version", "user-agent")


def redact(value: str | None) -> str | None:
    """Enough of a credential to recognise it ("Bearer atl-at.Xy…"), never the whole thing."""
    return None if value is None else value[:16] + "…"


def record(request: Request, **fields: Any) -> None:
    headers = {k: v for k, v in request.headers.items() if k in _LOGGED_HEADERS}
    headers["authorization"] = redact(request.headers.get("authorization"))
    headers["x-id-token"] = redact(request.headers.get("x-id-token"))
    _requests.append({
        "at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        **fields,
        "idTokenPresent": "x-id-token" in request.headers,
        "headers": headers,
    })


# ---------------------------------------------------------------------------
# MCP transport
# ---------------------------------------------------------------------------


@app.get("/mcp")
async def mcp_get() -> Response:
    """No SSE stream leg, exactly as the gateway does not offer one."""
    return JSONResponse(
        rpc_error(None, INVALID_REQUEST, "Server-Sent Events (SSE) not supported. Use POST (Streamable HTTP)."),
        status_code=405,
        headers={"Allow": "POST"},
    )


def _authenticate(request: Request) -> oauth.AccessToken:
    scheme, _, value = (request.headers.get("authorization") or "").partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        raise oauth.OAuthError("invalid_token", "A Bearer access token is required", 401)
    return oauth.lookup(value.strip())


@app.post("/mcp")
async def mcp_post(request: Request) -> Response:
    started = time.perf_counter()
    rpc_id: Any = None
    method = tool = None
    principal = "anonymous"
    status = "ok"
    try:
        try:
            body = json.loads(await request.body() or b"null")
        except json.JSONDecodeError as exc:
            raise RpcError(PARSE_ERROR, f"Invalid JSON: {exc.msg}") from exc
        if not isinstance(body, dict):
            raise RpcError(INVALID_REQUEST, "Request must be a single JSON-RPC object (batches are not supported)")
        rpc_id, method, params = body.get("id"), body.get("method"), body.get("params") or {}
        if body.get("jsonrpc") != "2.0":
            raise RpcError(INVALID_REQUEST, f"Unsupported jsonrpc version: {body.get('jsonrpc')!r}")
        if not isinstance(method, str) or not method:
            raise RpcError(INVALID_REQUEST, "Missing or invalid 'method'")
        if not isinstance(params, dict):
            raise RpcError(INVALID_PARAMS, "'params' must be an object")

        # Notifications (notifications/initialized, ...) carry no id and get no response body.
        if method.startswith("notifications/"):
            status = "202"
            return Response(status_code=202)

        if method == "tools/call":
            tool = params.get("name") if isinstance(params.get("name"), str) else None
            try:
                token = _authenticate(request)
            except oauth.OAuthError as exc:
                status = "401"
                log.warning("401 tools/call: %s", exc.description)
                return JSONResponse(
                    rpc_error(rpc_id, UNAUTHORIZED, f"Unauthorized: {exc.description}"),
                    status_code=401,
                    headers={"WWW-Authenticate": 'Bearer realm="atlassian", error="invalid_token"'},
                )
            principal = token.account
            result = call_tool(params, token)
        else:
            result = dispatch(method, params)

        response = JSONResponse(rpc_result(rpc_id, result))
        if method == "initialize":
            response.headers["Mcp-Session-Id"] = uuid.uuid4().hex
        return response

    except RpcError as exc:
        status = f"rpc{exc.code}"
        return JSONResponse(rpc_error(rpc_id, exc.code, exc.message))
    except Exception:  # noqa: BLE001 - never leak a stack trace to the client
        status = "500"
        log.exception("Unhandled error on %s", method)
        return JSONResponse(rpc_error(rpc_id, INTERNAL_ERROR, "Internal error in mock server"))
    finally:
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        record(request, method=method, id=rpc_id, tool=tool, status=status,
               principal=principal, durationMs=duration_ms)
        # One structured line per request. Never the token itself.
        log.info("mcp method=%s tool=%s status=%s principal=%s duration=%.1fms",
                 method, tool, status, principal, duration_ms)


def dispatch(method: str, params: dict[str, Any]) -> Any:
    """Everything except tools/call: no token needed."""
    if method == "initialize":
        return {
            "protocolVersion": PROTOCOL_VERSION,  # whatever the client asked for, this is what we speak
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "instructions": (
                "Read-only access to Jira issues and Bitbucket Cloud repositories for the "
                "example-corp site. Call getAccessibleAtlassianResources first if you need a cloud ID."
            ),
        }
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": [t.to_mcp() for t in TOOLS.values()]}
    if method == "resources/list":
        return {"resources": []}
    if method == "resources/templates/list":
        return {"resourceTemplates": []}
    if method == "prompts/list":
        return {"prompts": []}
    raise RpcError(METHOD_NOT_FOUND, f"Method not found: {method}")


def call_tool(params: dict[str, Any], token: oauth.AccessToken) -> dict[str, Any]:
    name = params.get("name")
    if not isinstance(name, str) or not name:
        raise RpcError(INVALID_PARAMS, "tools/call requires a 'name'")
    arguments = params.get("arguments") or {}
    if not isinstance(arguments, dict):
        raise RpcError(INVALID_PARAMS, "'arguments' must be an object")

    tool = TOOLS.get(name)
    if tool is None:
        return tool_result(f"Unknown tool: {name!r}. Available tools: {', '.join(sorted(TOOLS))}", is_error=True)

    # Atlassian holds the token to its scopes, whatever the gateway allows.
    missing = [s for s in tool.scopes if s not in token.scopes]
    if missing:
        return tool_result(
            f"The Atlassian grant for this account does not include {', '.join(missing)}, "
            f"which {name} requires.",
            is_error=True,
        )

    try:
        return tool_result(tool.handler(arguments, token.account))
    except ToolFailure as exc:
        return tool_result(str(exc), is_error=True)
    except InvalidParams as exc:
        raise RpcError(INVALID_PARAMS, str(exc)) from exc


# ---------------------------------------------------------------------------
# Observability, outside /mcp on purpose
# ---------------------------------------------------------------------------


@app.get("/healthz")
async def healthz() -> dict[str, Any]:
    return {
        "status": "ok",
        "server": SERVER_NAME,
        "version": SERVER_VERSION,
        "protocolVersion": PROTOCOL_VERSION,
        "tools": len(TOOLS),
        "oauthClientId": settings.oauth_client_id,
        "idjagIssuer": settings.idjag_issuer,
        "idjagAudience": settings.idjag_audience,
    }


@app.get("/admin/requests")
async def admin_requests() -> list[dict[str, Any]]:
    """Recent MCP requests, oldest first: what the gateway actually sent upstream."""
    return list(_requests)


def main() -> None:
    import uvicorn

    uvicorn.run(app, host=settings.host, port=settings.port, log_level=settings.log_level)


if __name__ == "__main__":
    main()
