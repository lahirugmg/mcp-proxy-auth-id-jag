"""Shared fixtures: a test client, and ID-JAGs signed by a key generated here.

The tests stand in for WSO2 IS by signing ID-JAGs with their own RSA key and
pre-loading its public half, so they need no running IdP.
"""

from __future__ import annotations

import json
import time
import uuid

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app import idjag, oauth
from app.config import settings
from app.main import app

KID = "test-idp-key"
IDP_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
CLIENT_ID = settings.oauth_client_id
CLIENT_SECRET = settings.oauth_client_secret


@pytest.fixture
def client():
    oauth.clear_state()
    idjag.clear_state()
    idjag.use_keys({KID: IDP_KEY.public_key()})
    with TestClient(app) as c:
        yield c
    oauth.clear_state()
    idjag.clear_state()


def id_jag(*, key=IDP_KEY, typ=idjag.ID_JAG_TYP, kid=KID, **overrides) -> str:
    """An ID-JAG shaped like the one WSO2 IS issues. Pass claim=None to drop a claim."""
    now = int(time.time())
    claims = {
        "iss": settings.idjag_issuer,
        "sub": "dana@example.com",
        "aud": settings.idjag_audience,
        "client_id": CLIENT_ID,
        "iat": now,
        "exp": now + 300,
        "jti": str(uuid.uuid4()),
        **overrides,
    }
    claims = {k: v for k, v in claims.items() if v is not None}
    return pyjwt.encode(claims, key, algorithm="RS256", headers={"typ": typ, "kid": kid})


def redeem(client, assertion, *, secret=CLIENT_SECRET, **form):
    """POST /oauth/token with the jwt-bearer grant, authenticating by client_secret_post."""
    return client.post("/oauth/token", data={
        "grant_type": idjag.JWT_BEARER, "assertion": assertion,
        "client_id": CLIENT_ID, "client_secret": secret, **form,
    })


def access_token(client, **claims) -> str:
    r = redeem(client, id_jag(**claims))
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def rpc(client, method, params=None, *, token=None, rpc_id=1):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    body = {"jsonrpc": "2.0", "id": rpc_id, "method": method, "params": params or {}}
    return client.post("/mcp", json=body, headers=headers)


def call(client, token, name, arguments=None):
    return rpc(client, "tools/call", {"name": name, "arguments": arguments or {}}, token=token)


def payload(response) -> dict:
    """Unwrap a successful tool result back into the object the handler returned."""
    result = response.json()["result"]
    assert result["isError"] is False, result
    return json.loads(result["content"][0]["text"])


def error_text(response) -> str:
    """The text of an isError tool result."""
    result = response.json()["result"]
    assert result["isError"] is True, result
    return result["content"][0]["text"]
