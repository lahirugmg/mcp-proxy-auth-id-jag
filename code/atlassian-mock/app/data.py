"""Fixture data and per-account visibility.

Everything is fictitious and static: a Jira site and a Bitbucket workspace for
"example-corp", and a handful of accounts that each see a different slice of
it. That per-account slice is what makes the per-user token observable: Dana
and Marta call the same tool with the same arguments and get different answers.

In the real world Atlassian applies its own permissions to whichever account a
token belongs to; accounts.json stands in for that.
"""

from __future__ import annotations

import json
from typing import Any

from .config import FIXTURES_DIR

WILDCARD = "*"


def _load(name: str) -> Any:
    with (FIXTURES_DIR / name).open(encoding="utf-8") as fh:
        return json.load(fh)


ACCOUNTS: dict[str, dict[str, Any]] = _load("accounts.json")  # account name -> profile and entitlements
RESOURCES: list[dict[str, Any]] = _load("resources.json")     # Atlassian sites (cloud IDs)
PROJECTS: list[dict[str, Any]] = _load("projects.json")
ISSUES: list[dict[str, Any]] = _load("issues.json")
REPOS: list[dict[str, Any]] = _load("repos.json")
PULL_REQUESTS: list[dict[str, Any]] = _load("pull_requests.json")
FILES: dict[str, dict[str, str]] = _load("files.json")         # repo slug -> path -> content


def email_for(account: str) -> str:
    return f"{account}@example.com"


def account_for_email(email: str) -> str | None:
    """The account an ID-JAG's `sub` (an email address) names, if any."""
    return next((a for a in ACCOUNTS if email_for(a) == email.strip().lower()), None)


# --- lookups -----------------------------------------------------------------


def issue(key: str) -> dict[str, Any] | None:
    return next((i for i in ISSUES if i["key"].upper() == key.upper()), None)


def repo(slug: str) -> dict[str, Any] | None:
    return next((r for r in REPOS if r["slug"].lower() == slug.lower()), None)


def prs_for_repo(slug: str, state: str | None = None) -> list[dict[str, Any]]:
    prs = [p for p in PULL_REQUESTS if p["repoSlug"].lower() == slug.lower()]
    return [p for p in prs if p["state"] == state] if state else prs


def prs_for_issue(key: str) -> list[dict[str, Any]]:
    return [p for p in PULL_REQUESTS if key.upper() in (k.upper() for k in p["issueKeys"])]


# --- per-account visibility ----------------------------------------------------


class AccessDenied(Exception):
    """The account is not entitled to the requested resource."""


def allowed_projects(account: str) -> list[str]:
    return ACCOUNTS[account]["projects"]


def allowed_repos(account: str) -> list[str]:
    return ACCOUNTS[account]["repos"]


def can_see_project(account: str, key: str) -> bool:
    allowed = allowed_projects(account)
    return WILDCARD in allowed or key.upper() in {a.upper() for a in allowed}


def can_see_repo(account: str, slug: str) -> bool:
    allowed = allowed_repos(account)
    return WILDCARD in allowed or slug.lower() in {a.lower() for a in allowed}


def require_project(account: str, key: str) -> None:
    if not can_see_project(account, key):
        raise AccessDenied(
            f"{account} does not have access to Jira project {key.upper()}. "
            f"Visible projects: {', '.join(sorted(allowed_projects(account)))}"
        )


def require_repo(account: str, slug: str) -> None:
    if not can_see_repo(account, slug):
        raise AccessDenied(
            f"{account} does not have access to Bitbucket repository {slug}. "
            f"Visible repositories: {', '.join(sorted(allowed_repos(account)))}"
        )
