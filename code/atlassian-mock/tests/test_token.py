"""POST /oauth/token: redeeming an ID-JAG with the RFC 7523 jwt-bearer grant."""

from __future__ import annotations

import base64
import time

from app import idjag
from app.config import settings

from conftest import CLIENT_ID, CLIENT_SECRET, OTHER_KEY, id_jag, redeem


def refused(response, error="invalid_grant", status=400) -> str:
    assert response.status_code == status, response.text
    assert response.json()["error"] == error
    return response.json()["error_description"]


# --- the happy path ---------------------------------------------------------------

def test_an_id_jag_buys_an_opaque_access_token_and_no_refresh_token(client):
    r = redeem(client, id_jag())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["access_token"].startswith("atl-at.")
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 3600
    assert body["scope"] == " ".join(settings.idjag_default_scopes)
    assert "refresh_token" not in body
    assert r.headers["cache-control"] == "no-store"


def test_client_secret_basic_is_accepted(client):
    basic = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
    r = client.post("/oauth/token", headers={"Authorization": f"Basic {basic}"},
                    data={"grant_type": idjag.JWT_BEARER, "assertion": id_jag()})
    assert r.status_code == 200, r.text


def test_the_grant_is_recorded_without_token_values(client):
    token = redeem(client, id_jag()).json()["access_token"]
    view = client.get("/admin/oauth/grants").json()
    assert view["total"] == view["active"] == 1
    grant = view["grants"][0]
    assert grant["account"] == "dana"
    assert grant["via"] == "id-jag"
    assert grant["clientId"] == CLIENT_ID
    assert grant["liveAccessTokens"] == 1 and grant["liveRefreshTokens"] == 0
    assert isinstance(grant["createdAt"], int)
    assert token not in str(view)


# --- scopes -------------------------------------------------------------------------

def test_scopes_carried_in_the_id_jag_are_granted(client):
    r = redeem(client, id_jag(scope="read:jira-work read:repository:bitbucket"))
    assert r.json()["scope"] == "read:jira-work read:repository:bitbucket"


def test_the_gateway_may_ask_for_less_than_the_id_jag_carries(client):
    r = redeem(client, id_jag(scope="read:jira-work read:repository:bitbucket"), scope="read:jira-work")
    assert r.json()["scope"] == "read:jira-work"


def test_the_gateway_may_not_ask_for_more_than_the_id_jag_carries(client):
    r = redeem(client, id_jag(scope="read:jira-work"), scope="write:jira-work")
    assert "write:jira-work" in refused(r, "invalid_scope")


def test_offline_access_is_never_granted(client):
    assert "offline_access" in refused(redeem(client, id_jag(scope="read:jira-work offline_access")), "invalid_scope")


# --- what must be refused ------------------------------------------------------------

def test_not_typed_as_an_id_jag(client):
    # An ID token, say, signed by the same IdP. typ is what keeps it out.
    assert "typ" in refused(redeem(client, id_jag(typ="JWT")))


def test_signed_by_a_key_the_idp_does_not_publish(client):
    assert "signature" in refused(redeem(client, id_jag(key=OTHER_KEY)))


def test_addressed_to_another_authorization_server(client):
    assert "not addressed to this server" in refused(redeem(client, id_jag(aud="https://auth.example.org")))


def test_from_another_issuer(client):
    assert "trusted IdP" in refused(redeem(client, id_jag(iss="https://idp.example.org")))


def test_expired(client):
    long_ago = int(time.time()) - 3600
    assert "expired" in refused(redeem(client, id_jag(iat=long_ago, exp=long_ago + 300)))


def test_within_the_clock_skew_leeway(client):
    just_now = int(time.time()) - 310  # exp 10 s ago, inside the 30 s leeway
    assert redeem(client, id_jag(iat=just_now, exp=just_now + 300)).status_code == 200


def test_issued_for_another_client(client):
    assert "not the client presenting it" in refused(redeem(client, id_jag(client_id="someone-else")))


def test_used_twice(client):
    assertion = id_jag()
    assert redeem(client, assertion).status_code == 200
    assert "already been used" in refused(redeem(client, assertion))


def test_missing_required_claim(client):
    refused(redeem(client, id_jag(jti=None)))


def test_user_with_no_atlassian_account(client):
    assert "No Atlassian account" in refused(redeem(client, id_jag(sub="nobody@example.com")))


def test_wrong_client_secret(client):
    refused(redeem(client, id_jag(), secret="wrong"), "invalid_client", 401)


def test_unsupported_grant_type(client):
    r = client.post("/oauth/token", data={
        "grant_type": "authorization_code", "code": "x",
        "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
    })
    refused(r, "unsupported_grant_type")


def test_missing_assertion(client):
    refused(redeem(client, ""), "invalid_request")
