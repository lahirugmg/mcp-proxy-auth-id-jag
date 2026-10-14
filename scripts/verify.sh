#!/usr/bin/env bash
#
# verify.sh — play GitHub Copilot's part with curl, end to end, and show the evidence.
#
#   1. Discovery: the gateway's resource metadata sends the client to sign in at /idp.
#   2. Sign-in: authorization code + PKCE at WSO2 IS (the browser part, done with curl),
#      the code exchanged through the gateway, which keeps the ID token.
#   3. Tool calls with only the IS access token: the gateway exchanges the ID token
#      for an ID-JAG, redeems it at the mock, and calls the tool as dana.
#   4. A refresh through the gateway returns a new ID token.

set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
need jq curl openssl
is_up && apim_up && mock_up || die "start the servers first: scripts/start.sh"

C=(curl -sk)
JSON=(-H "Content-Type: application/json")
REDIRECT_URI="http://127.0.0.1:33418/"   # VS Code's loopback listener
q() { jq -rn --arg v "$1" '$v|@uri'; }
b64url() { base64 | tr '+/' '-_' | tr -d '=\n'; }
claims() { cut -d. -f2 <<<"$1" | tr '_-' '/+' | awk '{ while (length($0) % 4) $0 = $0 "="; print }' | base64 -d 2>/dev/null; }
call() {   # call <access token> <tool> <arguments json>
  "${C[@]}" -w '\n%{http_code}' "$MCP_URL" "${JSON[@]}" ${1:+-H "Authorization: Bearer $1"} \
    -d "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"$2\",\"arguments\":$3}}"
}
APIM_LOG="$APIM_HOME/repository/logs/wso2carbon.log"
log_mark=$(wc -l < "$APIM_LOG")

say "1. Discovery"
resp=$(call "" atlassianUserInfo '{}'); echo "    tools/call without a token: HTTP ${resp##*$'\n'}"
rm_meta=$("${C[@]}" "$GATEWAY$MCP_CONTEXT/v1/.well-known/oauth-protected-resource")
echo "    resource metadata: $(jq -c '{authorization_servers, scopes_supported}' <<<"$rm_meta")"
meta=$("${C[@]}" "$(jq -r '.authorization_servers[0]' <<<"$rm_meta")/.well-known/openid-configuration")
authorize=$(jq -r .authorization_endpoint <<<"$meta"); token_ep=$(jq -r .token_endpoint <<<"$meta")
echo "    sign-in metadata: authorize at $authorize, tokens at $token_ep"

say "2. dana signs in (authorization code + PKCE)"
verifier=$(openssl rand -base64 48 | b64url)
challenge=$(printf '%s' "$verifier" | openssl dgst -sha256 -binary | b64url)
jar=$(mktemp); trap 'rm -f "$jar"' EXIT
B=(curl -sk -c "$jar" -b "$jar" -o /dev/null -w '%{redirect_url}')
next=$("${B[@]}" "$authorize?response_type=code&client_id=$COPILOT_CLIENT_ID&redirect_uri=$(q "$REDIRECT_URI")&scope=$(q "openid jira:read bitbucket:read")&state=s1&code_challenge=$challenge&code_challenge_method=S256&resource=$(q "$MCP_URL")")
sdk=$(sed -nE 's/.*[?&]sessionDataKey=([^&]+).*/\1/p' <<<"$next")
[[ -n "$sdk" ]] || die "IS did not show its login page: $next"
next=$("${B[@]}" "$IS_BASE/commonauth" --data-urlencode "usernameUserInput=$DEMO_USER" \
  --data-urlencode "username=$DEMO_USER" --data-urlencode "password=$DEMO_PASS" --data-urlencode "sessionDataKey=$sdk")
for _ in 1 2 3 4 5; do [[ "$next" == "$REDIRECT_URI"* || -z "$next" ]] && break; next=$("${B[@]}" "$next"); done
code=$(sed -nE 's/.*[?&]code=([^&]+).*/\1/p' <<<"$next")
[[ -n "$code" ]] || die "no authorization code; IS sent the browser to: $next"
tokens=$("${C[@]}" "$token_ep" -d grant_type=authorization_code -d "client_id=$COPILOT_CLIENT_ID" \
  --data-urlencode "code=$code" --data-urlencode "redirect_uri=$REDIRECT_URI" \
  --data-urlencode "code_verifier=$verifier" --data-urlencode "resource=$MCP_URL")
at=$(jq -r '.access_token // empty' <<<"$tokens"); rt=$(jq -r '.refresh_token // empty' <<<"$tokens")
[[ -n "$at" ]] || die "code exchange failed: $tokens"
echo "    code exchanged through the gateway: scope \"$(jq -r .scope <<<"$tokens")\""
echo "    ID token aud: $(claims "$(jq -r .id_token <<<"$tokens")" | jq -c .aud)"

say "3. Tool calls with only dana's IS access token"
ok=1
for t in 'atlassianUserInfo {}' 'searchJiraIssuesUsingJql {"jql":"project = OPS","maxResults":3}' \
         'searchBitbucketRepositories {"query":"platform"}'; do
  resp=$(call "$at" "${t%% *}" "${t#* }"); status=${resp##*$'\n'}
  echo "    ${t%% *}: HTTP $status  $(jq -r '.result.content[0].text // .error.message // .' <<<"${resp%$'\n'*}" 2>/dev/null | tr -d '\n' | head -c 90)"
  [[ "$status" == "200" ]] || ok=0
done

say "4. Refresh through the gateway"
refreshed=$("${C[@]}" "$token_ep" -d grant_type=refresh_token -d "client_id=$COPILOT_CLIENT_ID" --data-urlencode "refresh_token=$rt")
echo "    new access token: $(jq -r 'if .access_token then "yes" else "no" end' <<<"$refreshed"), new ID token: $(jq -r 'if .id_token then "yes" else "no" end' <<<"$refreshed")"

say "Evidence"
echo "    API Manager log:"
tail -n +"$((log_mark + 1))" "$APIM_LOG" | grep 'ID-JAG' | sed -E 's/^.*\[[0-9-]+ ([0-9:]+),[0-9]+\] +INFO \{[^}]*\} - /      \1 /' | cut -c1-170
echo "    Atlassian mock, latest grants (via id-jag) and requests:"
curl -s "$MOCK/admin/oauth/grants" | jq -r '(if type == "array" then . else .grants end) | .[-2:][] | "      \(.grantId)  account=\(.account)  via=\(.via)  clientId=\(.clientId)"'
curl -s "$MOCK/admin/requests" | jq -r '[.[] | select(.method == "tools/call")] | .[-2:][] | "      \(.tool)  principal=\(.principal)  authorization=\(.headers.authorization)  x-id-token=\(.headers["x-id-token"] // "absent")"'

[[ "$ok" == 1 ]] || die "a tool call failed"
say "All checks passed. Next: VS Code (README, step 5)"
