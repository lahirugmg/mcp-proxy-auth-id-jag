"""Atlassian's token endpoint, reduced to the one grant this demo uses.

    POST /oauth/token   grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
                        assertion=<ID-JAG signed by WSO2 IS>

The gateway authenticates as its registered client (client_secret_basic or
client_secret_post), presents an ID-JAG naming the user, and receives an opaque
access token for that user's Atlassian account. No consent screen and no
refresh token: when the token expires, the gateway presents a fresh ID-JAG.

The /mcp endpoint then accepts only tokens issued here, and answers with the
permissions of the account the token belongs to.
"""

from __future__ import annotations

import base64
import hmac
import json
import logging
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, unquote_plus

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from . import data, idjag
from .config import settings

log = logging.getLogger("atlassian-mock")
router = APIRouter()

# Scopes this authorization server knows. offline_access is deliberately absent:
# an ID-JAG never buys a refresh token.
KNOWN_SCOPES = frozenset({
    "read:jira-work", "write:jira-work", "read:jira-user", "read:me",
    "read:confluence-content.summary",
    "read:repository:bitbucket", "read:pullrequest:bitbucket", "write:pullrequest:bitbucket",
})


class OAuthError(Exception):
    """An RFC 6749 error response."""

    def __init__(self, error: str, description: str, status: int = 400) -> None:
        super().__init__(description)
        self.error, self.description, self.status = error, description, status


@dataclass(frozen=True)
class AccessToken:
    grant_id: str
    account: str
    client_id: str
    scopes: tuple[str, ...]
    created_at: float
    expires_at: float


_lock = threading.Lock()
_tokens: dict[str, AccessToken] = {}  # token value -> what it grants; one per redeemed ID-JAG


def clear_state() -> None:
    """Forget every issued token. Tests only."""
    with _lock:
        _tokens.clear()


# ---------------------------------------------------------------------------
# Token endpoint
# ---------------------------------------------------------------------------


def _same(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def authenticate_client(authorization: str | None, form: dict[str, str]) -> str:
    """client_secret_basic or client_secret_post (RFC 6749 section 2.3.1). Returns the client id."""
    client_id, secret = form.get("client_id", ""), form.get("client_secret", "")
    if authorization and authorization[:6].lower() == "basic ":
        try:
            decoded = base64.b64decode(authorization[6:].strip(), validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            raise OAuthError("invalid_client", "Malformed Basic credentials", 401) from None
        raw_id, _, raw_secret = decoded.partition(":")
        client_id, secret = unquote_plus(raw_id), unquote_plus(raw_secret)
    if not (_same(client_id, settings.oauth_client_id) and _same(secret, settings.oauth_client_secret)):
        raise OAuthError("invalid_client", "Client authentication failed", 401)
    return client_id


def redeem_id_jag(form: dict[str, str], client_id: str) -> dict[str, Any]:
    """Issue an access token for the user the ID-JAG names.

    Scopes: what the gateway asks for, within what the ID-JAG carries; or,
    when the ID-JAG carries none, this server's default set.
    """
    try:
        claims = idjag.verify(form.get("assertion", ""), client_id)
    except idjag.IdJagError as exc:
        log.warning("id-jag refused client=%s reason=%s", client_id, exc)
        raise OAuthError("invalid_grant", str(exc)) from None

    account = data.account_for_email(str(claims["sub"]))
    if account is None:
        raise OAuthError("invalid_grant", f"No Atlassian account for {claims['sub']!r}")

    allowed = tuple(str(claims.get("scope", "")).split()) or settings.idjag_default_scopes
    asked = tuple(form.get("scope", "").split())
    beyond = [s for s in asked if s not in allowed]
    if beyond:
        raise OAuthError("invalid_scope", f"Not covered by the ID-JAG: {' '.join(beyond)}")
    scopes = asked or allowed
    unknown = [s for s in scopes if s not in KNOWN_SCOPES]
    if unknown:
        raise OAuthError("invalid_scope", f"Not available through an ID-JAG: {' '.join(unknown)}")

    now = time.time()
    value = "atl-at." + secrets.token_urlsafe(32)
    token = AccessToken(
        grant_id="grant-" + secrets.token_hex(6),
        account=account,
        client_id=client_id,
        scopes=scopes,
        created_at=now,
        expires_at=now + settings.access_token_ttl,
    )
    with _lock:
        _tokens[value] = token
    log.info(
        "id-jag redeemed sub=%s account=%s client=%s scopes=%r grant=%s",
        claims["sub"], account, client_id, " ".join(scopes), token.grant_id,
    )
    return {
        "access_token": value,
        "token_type": "Bearer",
        "expires_in": settings.access_token_ttl,
        "scope": " ".join(scopes),
    }


def _parse_body(raw: bytes, content_type: str) -> dict[str, str]:
    text = raw.decode("utf-8", "replace")
    if "application/json" in content_type:
        try:
            body = json.loads(text or "{}")
        except json.JSONDecodeError:
            return {}
        return {str(k): str(v) for k, v in body.items()} if isinstance(body, dict) else {}
    return dict(parse_qsl(text, keep_blank_values=True))


_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


@router.post("/oauth/token")
async def token_endpoint(request: Request) -> JSONResponse:
    form = _parse_body(await request.body(), request.headers.get("content-type", ""))
    try:
        client_id = authenticate_client(request.headers.get("authorization"), form)
        grant_type = form.get("grant_type")
        if not grant_type:
            raise OAuthError("invalid_request", "Parameter 'grant_type' is required")
        if grant_type != idjag.JWT_BEARER:
            raise OAuthError("unsupported_grant_type", f"grant_type {grant_type!r} is not supported")
        if not form.get("assertion"):
            raise OAuthError("invalid_request", "Parameter 'assertion' is required")
        body = redeem_id_jag(form, client_id)
    except OAuthError as exc:
        headers = dict(_NO_STORE)
        if exc.status == 401:
            headers["WWW-Authenticate"] = 'Basic realm="atlassian"'
        return JSONResponse(
            {"error": exc.error, "error_description": exc.description},
            status_code=exc.status,
            headers=headers,
        )
    return JSONResponse(body, headers=_NO_STORE)


# ---------------------------------------------------------------------------
# Resource server side: the tokens /mcp accepts
# ---------------------------------------------------------------------------


def lookup(value: str) -> AccessToken:
    """The live access token behind a bearer value, or OAuthError(invalid_token)."""
    with _lock:
        token = _tokens.get(value)
    if token is None:
        raise OAuthError("invalid_token", "Atlassian access token is not recognised", 401)
    if token.expires_at <= time.time():
        raise OAuthError("invalid_token", "Atlassian access token has expired", 401)
    return token


@router.get("/admin/oauth/grants")
async def admin_grants() -> dict[str, Any]:
    """One row per redeemed ID-JAG. Metadata only, never token values."""
    now = time.time()
    with _lock:
        tokens = sorted(_tokens.values(), key=lambda t: t.created_at)
    rows = [
        {
            "grantId": t.grant_id,
            "account": t.account,
            "via": "id-jag",
            "clientId": t.client_id,
            "scopes": list(t.scopes),
            "createdAt": int(t.created_at),
            "expiresAt": int(t.expires_at),
            "liveAccessTokens": 1 if t.expires_at > now else 0,
            "liveRefreshTokens": 0,
        }
        for t in tokens
    ]
    return {"total": len(rows), "active": sum(r["liveAccessTokens"] for r in rows), "grants": rows}
