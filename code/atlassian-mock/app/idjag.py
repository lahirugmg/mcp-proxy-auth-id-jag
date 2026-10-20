"""Verifies an ID-JAG presented in an RFC 7523 jwt-bearer grant.

The gateway obtained the ID-JAG (Identity Assertion JWT Authorization Grant)
from WSO2 IS and presents it at /oauth/token. This module decides whether to
believe it; oauth.py then issues the access token.

The checks follow the resource authorization server's processing rules in
draft-ietf-oauth-identity-assertion-authz-grant:

    typ        the JWT header says oauth-id-jag+jwt, so no other JWT the IdP
               signs (an ID token, say) can be replayed here
    signature  by a key the trusted IdP publishes at its JWKS URL
    iss        is the trusted IdP
    aud        is this authorization server
    exp, iat   current (30 s leeway)
    client_id  is the client authenticating this token request
    jti        not seen before (single use)

Every failure is invalid_grant, as RFC 7523 section 3.1 specifies.
"""

from __future__ import annotations

import json
import ssl
import threading
import time
import urllib.request
from typing import Any

import jwt as pyjwt

from .config import settings

JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
ID_JAG_TYP = "oauth-id-jag+jwt"
ALGORITHMS = ["RS256", "PS256", "ES256"]
LEEWAY_SECONDS = 30


class IdJagError(Exception):
    """The assertion is not an ID-JAG this server will honour."""


_lock = threading.Lock()
_keys: dict[str, Any] = {}       # kid -> public key, from the IdP's JWKS
_seen_jti: dict[str, float] = {}  # jti -> exp, kept until the ID-JAG would have expired anyway


def clear_state() -> None:
    """Forget cached keys and seen jti values. Tests only."""
    with _lock:
        _keys.clear()
        _seen_jti.clear()


def use_keys(keys: dict[str, Any]) -> None:
    """Pre-load signing keys by kid instead of fetching the JWKS. Tests only."""
    with _lock:
        _keys.update(keys)


def _tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not settings.idp_verify_tls:
        # A local WSO2 IS ships a self-signed certificate.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _signing_key(kid: str | None) -> Any:
    if not kid:
        raise IdJagError("The ID-JAG header carries no kid")
    with _lock:
        if kid in _keys:
            return _keys[kid]
    # Unknown kid: fetch the JWKS (again), in case the IdP rotated its keys.
    try:
        with urllib.request.urlopen(
            settings.idjag_jwks_url, timeout=settings.idp_timeout_seconds, context=_tls_context()
        ) as response:
            jwks = json.loads(response.read().decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise IdJagError(f"Could not fetch the IdP's JWKS from {settings.idjag_jwks_url}: {exc}") from exc
    with _lock:
        for entry in jwks.get("keys", []):
            try:
                _keys[entry["kid"]] = pyjwt.PyJWK(entry).key
            except Exception:  # noqa: BLE001 - skip keys PyJWT cannot model
                continue
        if kid not in _keys:
            raise IdJagError(f"The ID-JAG is signed with a key the IdP does not publish (kid={kid!r})")
        return _keys[kid]


def _check_audience(aud: Any) -> None:
    """draft-ietf-oauth-identity-assertion-authz-grant section 4.4.1: aud must
    identify a single authorization server, as a string or a one-element array."""
    if isinstance(aud, list):
        if len(aud) != 1:
            raise IdJagError(f"The ID-JAG's aud must name a single authorization server, not {aud!r}")
        aud = aud[0]
    if aud != settings.idjag_audience:
        raise IdJagError(f"The ID-JAG is not addressed to this server ({settings.idjag_audience})")


def verify(assertion: str, client_id: str) -> dict[str, Any]:
    """Return the ID-JAG's claims, or raise IdJagError saying why not."""
    if not assertion:
        raise IdJagError("Parameter 'assertion' is required")
    try:
        header = pyjwt.get_unverified_header(assertion)
    except pyjwt.PyJWTError as exc:
        raise IdJagError(f"The assertion is not a JWT: {exc}") from exc
    if header.get("typ") != ID_JAG_TYP:
        raise IdJagError(f"The assertion's typ is {header.get('typ')!r}, not {ID_JAG_TYP!r}")

    try:
        claims = pyjwt.decode(
            assertion,
            _signing_key(header.get("kid")),
            algorithms=ALGORITHMS,
            issuer=settings.idjag_issuer,
            leeway=LEEWAY_SECONDS,
            # aud is checked by hand below: PyJWT's own audience check accepts an
            # array with any number of matching elements, not just one.
            options={"require": ["iss", "sub", "aud", "exp", "iat", "jti"], "verify_aud": False},
        )
    except pyjwt.InvalidSignatureError as exc:
        raise IdJagError("The ID-JAG's signature does not verify against the IdP's keys") from exc
    except pyjwt.InvalidIssuerError as exc:
        raise IdJagError(f"The ID-JAG is not from the trusted IdP {settings.idjag_issuer}") from exc
    except pyjwt.ExpiredSignatureError as exc:
        raise IdJagError("The ID-JAG has expired") from exc
    except pyjwt.PyJWTError as exc:
        raise IdJagError(f"The ID-JAG is invalid: {exc}") from exc

    _check_audience(claims.get("aud"))

    if claims.get("client_id") != client_id:
        raise IdJagError(
            f"The ID-JAG was issued for client {claims.get('client_id')!r}, "
            f"not the client presenting it ({client_id!r})"
        )

    # Single use: remember each jti until its ID-JAG would have expired anyway.
    now = time.time()
    with _lock:
        for jti in [j for j, exp in _seen_jti.items() if exp + LEEWAY_SECONDS < now]:
            del _seen_jti[jti]
        if claims["jti"] in _seen_jti:
            raise IdJagError("The ID-JAG has already been used")
        _seen_jti[claims["jti"]] = float(claims["exp"])
    return claims
