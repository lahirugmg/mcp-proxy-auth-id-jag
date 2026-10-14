"""Runtime configuration, read from environment variables.

Every default pairs with the local demo stack (WSO2 IS on 9444, this mock on
9500), so the mock runs without any configuration at all.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"

# The MCP protocol revision WSO2 API Manager 4.6.0 accepts, and the only one
# this server speaks.
PROTOCOL_VERSION = "2025-06-18"
SERVER_NAME = "atlassian-rovo-mock"
SERVER_VERSION = "1.0.0"


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default).strip()


@dataclass(frozen=True)
class Settings:
    host: str = _env("HOST", "0.0.0.0")
    port: int = int(_env("PORT", "9500"))
    log_level: str = _env("LOG_LEVEL", "info").lower()

    # The one OAuth client allowed at /oauth/token: the WSO2 API Manager gateway.
    oauth_client_id: str = _env("OAUTH_CLIENT_ID", "wso2-mcp-gateway")
    oauth_client_secret: str = _env("OAUTH_CLIENT_SECRET", "wso2-gateway-atlassian-secret-abc123")
    access_token_ttl: int = int(_env("ACCESS_TOKEN_TTL", "3600"))

    # The identity provider whose ID-JAGs this server trusts (WSO2 IS), and this
    # server's own identifier: the `aud` an ID-JAG must carry to be redeemed here.
    idjag_issuer: str = _env("IDJAG_ISSUER", "https://localhost:9444/oauth2/token")
    idjag_jwks_url: str = _env("IDJAG_JWKS_URL", "https://localhost:9444/oauth2/jwks")
    idjag_audience: str = _env("IDJAG_AUDIENCE", "http://localhost:9500")
    # Granted when the ID-JAG carries no `scope` claim and the gateway asks for none.
    # Read-only, like the tool set: Jira and Bitbucket.
    idjag_default_scopes: tuple[str, ...] = tuple(
        _env(
            "IDJAG_DEFAULT_SCOPES",
            "read:jira-work read:confluence-content.summary "
            "read:repository:bitbucket read:pullrequest:bitbucket",
        ).split()
    )

    # Fetching the JWKS from WSO2 IS. A local IS ships a self-signed certificate,
    # so TLS verification is off by default; set IDP_VERIFY_TLS=true once the IS
    # certificate is trusted.
    idp_verify_tls: bool = _env("IDP_VERIFY_TLS", "false").lower() in {"1", "true", "yes", "on"}
    idp_timeout_seconds: int = int(_env("IDP_TIMEOUT_SECONDS", "6"))


settings = Settings()
