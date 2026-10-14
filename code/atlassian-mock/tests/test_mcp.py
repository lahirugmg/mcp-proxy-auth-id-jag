"""POST /mcp: protocol basics, token enforcement, per-user data and scopes."""

from __future__ import annotations

import pytest

from app import oauth
from app.config import PROTOCOL_VERSION

from conftest import access_token, call, error_text, payload, rpc

READ_ONLY_TOOLS = {
    "atlassianUserInfo", "getAccessibleAtlassianResources", "getVisibleJiraProjects",
    "searchJiraIssuesUsingJql", "getJiraIssue", "getJiraIssueRemoteIssueLinks",
    "searchBitbucketRepositories", "listBitbucketPullRequests", "getBitbucketFileContent",
}


# --- protocol, all anonymous --------------------------------------------------------

def test_initialize_pins_the_protocol_revision_and_opens_a_session(client):
    r = rpc(client, "initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                   "clientInfo": {"name": "pytest", "version": "1"}})
    assert r.status_code == 200
    assert r.json()["result"]["protocolVersion"] == PROTOCOL_VERSION == "2025-06-18"
    assert r.headers["mcp-session-id"]


def test_notification_is_accepted_with_no_body(client):
    r = client.post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert r.status_code == 202 and r.content == b""


def test_ping_and_empty_lists(client):
    assert rpc(client, "ping").json()["result"] == {}
    assert rpc(client, "resources/list").json()["result"] == {"resources": []}
    assert rpc(client, "prompts/list").json()["result"] == {"prompts": []}


def test_get_is_405(client):
    r = client.get("/mcp")
    assert r.status_code == 405 and r.headers["allow"] == "POST"


@pytest.mark.parametrize("body, code", [
    (b"{not json", -32700),
    (b'[{"jsonrpc": "2.0", "id": 1, "method": "ping"}]', -32600),
    (b'{"jsonrpc": "1.0", "id": 1, "method": "ping"}', -32600),
    (b'{"jsonrpc": "2.0", "id": 1, "method": "resources/subscribe"}', -32601),
])
def test_protocol_errors_are_json_rpc_errors(client, body, code):
    r = client.post("/mcp", content=body, headers={"Content-Type": "application/json"})
    assert r.json()["error"]["code"] == code


def test_tools_list_is_anonymous_and_has_exactly_the_nine_read_only_tools(client):
    tools = rpc(client, "tools/list").json()["result"]["tools"]
    assert {t["name"] for t in tools} == READ_ONLY_TOOLS
    assert all(t["annotations"]["readOnlyHint"] for t in tools)
    jql = next(t for t in tools if t["name"] == "searchJiraIssuesUsingJql")
    assert jql["inputSchema"]["required"] == ["jql"]


# --- tools/call needs a token this server issued ------------------------------------

@pytest.mark.parametrize("token", [None, "atl-at.not-issued-here", "eyJhbGciOiJSUzI1NiJ9.e30.x"])
def test_tools_call_without_a_valid_token_is_401(client, token):
    r = call(client, token, "getVisibleJiraProjects")
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == 'Bearer realm="atlassian", error="invalid_token"'
    assert r.json()["error"]["code"] == -32001


def test_basic_auth_is_not_a_bearer_token(client):
    r = client.post("/mcp", headers={"Authorization": "Basic abc"},
                    json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "ping"}})
    assert r.status_code == 401


def test_expired_token_is_401(client):
    token = access_token(client)
    with oauth._lock:
        record = oauth._tokens[token]
        oauth._tokens[token] = oauth.AccessToken(**{**record.__dict__, "expires_at": 0})
    assert call(client, token, "atlassianUserInfo").status_code == 401


def test_request_log_redacts_the_token_and_names_the_account(client):
    token = access_token(client)
    call(client, token, "atlassianUserInfo")
    rpc(client, "tools/list")
    authed, anonymous = client.get("/admin/requests").json()[-2:]
    assert authed["principal"] == "dana" and authed["tool"] == "atlassianUserInfo"
    assert authed["headers"]["authorization"] == f"Bearer {token}"[:16] + "…"
    assert token not in str(authed)
    assert authed["headers"]["x-id-token"] is None and authed["idTokenPresent"] is False
    assert anonymous["principal"] == "anonymous" and anonymous["headers"]["authorization"] is None


def test_unknown_tool_and_missing_argument(client):
    token = access_token(client)
    assert "Unknown tool" in error_text(call(client, token, "createJiraIssue"))
    assert call(client, token, "getJiraIssue").json()["error"]["code"] == -32602


# --- the token's account decides what comes back ----------------------------------

def test_user_info_is_the_end_user(client):
    me = payload(call(client, access_token(client), "atlassianUserInfo"))
    assert (me["username"], me["emailAddress"]) == ("dana", "dana@example.com")


def test_dana_sees_ops_and_plat_only(client):
    dana = access_token(client)
    projects = payload(call(client, dana, "getVisibleJiraProjects"))["projects"]
    assert [p["key"] for p in projects] == ["OPS", "PLAT"]
    issues = payload(call(client, dana, "searchJiraIssuesUsingJql", {"jql": "text ~ \"\"", "maxResults": 100}))["issues"]
    assert issues and {i["project"] for i in issues} <= {"OPS", "PLAT"}
    assert "does not have access" in error_text(call(client, dana, "getJiraIssue", {"issueKey": "WEB-11"}))


def test_marta_sees_a_different_slice(client):
    marta = access_token(client, sub="marta@example.com")
    projects = payload(call(client, marta, "getVisibleJiraProjects"))["projects"]
    assert [p["key"] for p in projects] == ["WEB"]
    assert "does not have access" in error_text(call(client, marta, "getJiraIssue", {"issueKey": "OPS-42"}))


def test_jira_and_bitbucket_tools_work_for_dana(client):
    dana = access_token(client)
    issue = payload(call(client, dana, "getJiraIssue", {"issueKey": "OPS-42"}))
    assert issue["assignee"]["displayName"] == "Dana Whitfield"
    links = payload(call(client, dana, "getJiraIssueRemoteIssueLinks", {"issueKey": "OPS-42"}))
    assert links["total"] > 0
    jql = payload(call(client, dana, "searchJiraIssuesUsingJql", {"jql": 'project = OPS AND status = "In Progress"'}))
    assert jql["total"] > 0 and all(i["status"] == "In Progress" for i in jql["issues"])
    repos = payload(call(client, dana, "searchBitbucketRepositories", {"query": "a"}))["repositories"]
    assert {r["slug"] for r in repos} == {"platform-api", "infra-terraform"}
    prs = payload(call(client, dana, "listBitbucketPullRequests", {"repoSlug": "platform-api", "state": "OPEN"}))
    assert prs["total"] > 0
    readme = payload(call(client, dana, "getBitbucketFileContent", {"repoSlug": "platform-api", "path": "README.md"}))
    assert readme["content"].startswith("# Platform API")
    assert "does not have access" in error_text(
        call(client, dana, "listBitbucketPullRequests", {"repoSlug": "web-frontend"}))


# --- scopes are enforced against the token -----------------------------------------

def test_a_token_without_bitbucket_scopes_cannot_read_bitbucket(client):
    jira_only = access_token(client, scope="read:jira-work")
    assert payload(call(client, jira_only, "getVisibleJiraProjects"))["total"] == 2
    denied = error_text(call(client, jira_only, "searchBitbucketRepositories", {"query": "api"}))
    assert "read:repository:bitbucket" in denied
    assert "read:pullrequest:bitbucket" in error_text(
        call(client, jira_only, "listBitbucketPullRequests", {"repoSlug": "platform-api"}))


def test_a_token_without_jira_scope_cannot_read_jira(client):
    bitbucket_only = access_token(client, scope="read:repository:bitbucket")
    assert "read:jira-work" in error_text(call(client, bitbucket_only, "getJiraIssue", {"issueKey": "OPS-42"}))
    # Tools that need no scope still answer.
    assert payload(call(client, bitbucket_only, "atlassianUserInfo"))["username"] == "dana"


def test_healthz(client):
    health = client.get("/healthz").json()
    assert health["status"] == "ok" and health["tools"] == 9
    assert health["oauthClientId"] == "wso2-mcp-gateway"
