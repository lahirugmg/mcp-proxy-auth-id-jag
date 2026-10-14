"""The nine read-only MCP tools.

Names and input schemas mirror the real Atlassian Rovo MCP Server. Every
handler receives the account the caller's access token belongs to, and answers
with only what that account may see.

Each tool also names the OAuth scopes it needs. Atlassian enforces those
against the token, not the gateway: a token granted without Bitbucket scopes
cannot read Bitbucket, whatever the gateway's own policy says.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

from . import data
from .data import AccessDenied


class ToolFailure(Exception):
    """A tool-level failure, reported as an isError result (not a JSON-RPC error)."""


class InvalidParams(Exception):
    """A missing or malformed required argument, reported as JSON-RPC -32602."""


def _require(args: dict[str, Any], key: str) -> str:
    value = args.get(key)
    if not isinstance(value, str) or not value.strip():
        raise InvalidParams(f"Missing required argument: {key!r}")
    return value.strip()


def _visible_issue(account: str, key: str) -> dict[str, Any]:
    issue = data.issue(key)
    if issue is None:
        raise ToolFailure(f"Issue {key!r} not found.")
    try:
        data.require_project(account, issue["project"])
    except AccessDenied as exc:
        raise ToolFailure(str(exc)) from exc
    return issue


def _visible_repo(account: str, slug: str, not_found: str) -> dict[str, Any]:
    repo = data.repo(slug)
    if repo is None:
        raise ToolFailure(not_found)
    try:
        data.require_repo(account, repo["slug"])
    except AccessDenied as exc:
        raise ToolFailure(str(exc)) from exc
    return repo


# --- Jira ----------------------------------------------------------------------


def atlassian_user_info(args: dict[str, Any], account: str) -> Any:
    """The account the access token belongs to: the end user, not a service account."""
    profile = data.ACCOUNTS[account]
    return {
        "accountId": profile["accountId"],
        "displayName": profile["displayName"],
        "emailAddress": data.email_for(account),
        "accountType": "atlassian",
        "active": True,
        "username": account,
        "sessionType": "user",
        "visibleProjects": profile["projects"],
        "visibleRepositories": profile["repos"],
        "note": "MOCK: identity of the Atlassian account the ID-JAG named when this access token was issued.",
    }


def get_accessible_resources(args: dict[str, Any], account: str) -> Any:
    return data.RESOURCES


def get_visible_projects(args: dict[str, Any], account: str) -> Any:
    search = (args.get("searchString") or "").strip().lower()
    projects = [p for p in data.PROJECTS if data.can_see_project(account, p["key"])]
    if search:
        projects = [p for p in projects if search in p["key"].lower() or search in p["name"].lower()]
    return {"total": len(projects), "projects": projects}


def get_issue(args: dict[str, Any], account: str) -> Any:
    return _visible_issue(account, _require(args, "issueKey"))


def get_remote_issue_links(args: dict[str, Any], account: str) -> Any:
    key = _require(args, "issueKey")
    _visible_issue(account, key)
    links: list[dict[str, Any]] = []
    for pr in data.prs_for_issue(key):
        links.append({
            "type": "pullrequest",
            "repoSlug": pr["repoSlug"],
            "id": pr["id"],
            "title": pr["title"],
            "state": pr["state"],
            "author": pr["author"],
            "sourceBranch": pr["sourceBranch"],
            "destinationBranch": pr["destinationBranch"],
            "url": pr["url"],
        })
        links.append({
            "type": "branch",
            "repoSlug": pr["repoSlug"],
            "name": pr["sourceBranch"],
            "url": f"{pr['url'].rsplit('/pull-requests', 1)[0]}/branch/{pr['sourceBranch']}",
        })
    return {"issueKey": key.upper(), "total": len(links), "links": links}


# A small JQL subset:  field = "value" | field != value | text ~ "term", joined by AND or OR.
_CLAUSE = re.compile(r"""(?P<field>[A-Za-z]+)\s*(?P<op>!=|=|~)\s*(?P<value>"[^"]*"|'[^']*'|[^\s()]+)""")
_FIELDS = {
    "project": "project", "status": "status", "assignee": "assignee", "priority": "priority",
    "issuetype": "issueType", "type": "issueType", "labels": "labels", "reporter": "reporter",
}


def _matches(issue: dict[str, Any], field: str, op: str, value: str) -> bool:
    value = value.lower()
    if field.lower() == "text":
        return value in " ".join([issue["key"], issue["summary"], issue.get("description", "")]).lower()

    mapped = _FIELDS.get(field.lower())
    if mapped is None:
        raise ToolFailure(f"Unsupported JQL field {field!r}. Supported: {', '.join(sorted(_FIELDS))}, text")
    actual = issue.get(mapped)
    if mapped in ("assignee", "reporter"):
        actual = (actual or {}).get("displayName", "")
    values = [str(v).lower() for v in (actual if isinstance(actual, list) else [actual])]

    hit = any(value in v for v in values) if op == "~" else value in values
    return hit if op in ("=", "~") else not hit


def search_issues_jql(args: dict[str, Any], account: str) -> Any:
    jql = _require(args, "jql")
    max_results = args.get("maxResults", 25)
    if not isinstance(max_results, int) or max_results < 1:
        max_results = 25
    max_results = min(max_results, 100)

    clauses = [
        (c.group("field"), c.group("op"), c.group("value").strip("\"'")) for c in _CLAUSE.finditer(jql)
    ]
    if not clauses:
        raise ToolFailure(
            f"Could not parse JQL: {jql!r}. Expected clauses like project = OPS AND status = \"In Progress\"."
        )
    combine = any if " or " in jql.lower() else all

    results = [
        i for i in data.ISSUES
        if data.can_see_project(account, i["project"]) and combine(_matches(i, *c) for c in clauses)
    ]
    return {"jql": jql, "total": len(results), "returned": min(len(results), max_results),
            "issues": results[:max_results]}


# --- Bitbucket -------------------------------------------------------------------


def search_repositories(args: dict[str, Any], account: str) -> Any:
    query = _require(args, "query").lower()
    hits = [
        r for r in data.REPOS
        if data.can_see_repo(account, r["slug"])
        and any(query in r[f].lower() for f in ("slug", "name", "language", "description"))
    ]
    return {"query": query, "total": len(hits), "repositories": hits}


def list_pull_requests(args: dict[str, Any], account: str) -> Any:
    slug = _require(args, "repoSlug")
    visible = sorted(r["slug"] for r in data.REPOS if data.can_see_repo(account, r["slug"]))
    repo = _visible_repo(account, slug, f"Repository {slug!r} not found. Visible repositories: {', '.join(visible)}")

    state = args.get("state")
    if state is not None:
        if not isinstance(state, str) or state.upper() not in {"OPEN", "MERGED", "DECLINED"}:
            raise ToolFailure("state must be one of OPEN, MERGED, DECLINED.")
        state = state.upper()

    prs = data.prs_for_repo(repo["slug"], state)
    return {"repoSlug": repo["slug"], "state": state or "ALL", "total": len(prs), "pullRequests": prs}


def get_file_content(args: dict[str, Any], account: str) -> Any:
    slug, path = _require(args, "repoSlug"), _require(args, "path")
    repo = _visible_repo(account, slug, f"Repository {slug!r} not found.")
    files = data.FILES.get(repo["slug"], {})
    content = files.get(path.lstrip("/"))
    if content is None:
        raise ToolFailure(f"File {path!r} not found in {slug!r}. Available: {', '.join(sorted(files)) or 'none'}")
    return {
        "repoSlug": repo["slug"],
        "path": path,
        "ref": args.get("ref") or repo["mainBranch"],
        "size": len(content),
        "content": content,
    }


# --- Catalogue -------------------------------------------------------------------


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    properties: dict[str, Any]
    required: tuple[str, ...]
    scopes: tuple[str, ...]  # OAuth scopes the access token must carry
    handler: Callable[[dict[str, Any], str], Any]

    def to_mcp(self) -> dict[str, Any]:
        """The tool descriptor tools/list returns."""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": {
                "type": "object",
                "properties": self.properties,
                "required": list(self.required),
                "additionalProperties": False,
            },
            "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True},
        }


def _str(description: str, **extra: Any) -> dict[str, Any]:
    return {"type": "string", "description": description, **extra}


JIRA, REPO, PULLS = ("read:jira-work",), ("read:repository:bitbucket",), ("read:pullrequest:bitbucket",)
ISSUE_KEY = {"issueKey": _str("Issue key, e.g. OPS-42.")}
REPO_SLUG = _str("Repository slug, e.g. platform-api.")

TOOLS: dict[str, Tool] = {t.name: t for t in [
    Tool("atlassianUserInfo",
         "Get the profile of the Atlassian account the current credential belongs to.",
         {}, (), (), atlassian_user_info),
    Tool("getAccessibleAtlassianResources",
         "List the Atlassian sites (cloud IDs) reachable with the current credential. "
         "Call this first to obtain the cloudId required by other tools.",
         {}, (), (), get_accessible_resources),
    Tool("getVisibleJiraProjects",
         "List Jira projects visible to the current credential. "
         "Optionally filter by a search string matched against key and name.",
         {"searchString": _str("Filter on project key or name.")}, (), JIRA, get_visible_projects),
    Tool("getJiraIssue",
         "Fetch a single Jira issue by its key, for example 'OPS-42'. "
         "Returns summary, status, assignee, priority, labels and description.",
         ISSUE_KEY, ("issueKey",), JIRA, get_issue),
    Tool("searchJiraIssuesUsingJql",
         "Search Jira issues with a JQL query. Supports project, status, "
         "assignee, priority, issuetype and labels with the '=' and '!=' operators, "
         "plus 'text ~ \"...\"' for free-text search.",
         {"jql": _str('e.g. project = OPS AND status = "In Progress"'),
          "maxResults": {"type": "integer", "description": "Default 25, maximum 100."}},
         ("jql",), JIRA, search_issues_jql),
    Tool("getJiraIssueRemoteIssueLinks",
         "List development artefacts linked to a Jira issue — Bitbucket "
         "pull requests and branches that reference the issue key.",
         ISSUE_KEY, ("issueKey",), JIRA, get_remote_issue_links),
    Tool("searchBitbucketRepositories",
         "Search Bitbucket Cloud repositories by name, slug, language or description.",
         {"query": _str("Free-text search term.")}, ("query",), REPO, search_repositories),
    Tool("listBitbucketPullRequests",
         "List pull requests in a Bitbucket repository, optionally filtered by state.",
         {"repoSlug": REPO_SLUG,
          "state": _str("Filter by pull request state.", enum=["OPEN", "MERGED", "DECLINED"])},
         ("repoSlug",), PULLS, list_pull_requests),
    Tool("getBitbucketFileContent",
         "Read the contents of a file from a Bitbucket repository at a given ref.",
         {"repoSlug": REPO_SLUG,
          "path": _str("Path within the repository, e.g. README.md."),
          "ref": _str("Branch or tag. Defaults to the main branch.")},
         ("repoSlug", "path"), REPO, get_file_content),
]}
