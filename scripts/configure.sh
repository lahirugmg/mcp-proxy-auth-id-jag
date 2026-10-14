#!/usr/bin/env bash
#
# configure.sh — everything the flow needs inside the running servers, through
# their REST APIs. Run after scripts/start.sh. Safe to re-run.
#
#   WSO2 IS
#     1. User dana, with an email address (the ID-JAG's sub).
#     2. App "MCP Gateway", client ID wso2-mcp-gateway: the gateway's own client,
#        allowed the token exchange grant (ID token -> ID-JAG).
#     3. App "GitHub Copilot VS Code", client ID vscode-copilot: public, PKCE,
#        loopback redirects; its ID tokens also name wso2-mcp-gateway as audience,
#        so the gateway may exchange them.
#     4. Tool scopes jira:read and bitbucket:read, granted through the role
#        atlassian-tools-user, which dana holds.
#   API Manager
#     5. WSO2 IS as a Key Manager, so APIM accepts IS-issued tokens.
#     6. MCP server AtlassianRovo in front of the mock, 9 tools with per-tool scopes.
#     7. Custom policies idJagTokenExchange and idpProxy (code/apim-idjag-policy/policy).
#     8. idJagTokenExchange deployed as a gateway policy.
#     9. REST API /idp, relaying IS's sign-in metadata and token endpoint.
#    10. Application CopilotVSCode, subscribed to the MCP server, with vscode-copilot as its keys.

set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
need jq curl python3
is_up && apim_up && mock_up || die "start the servers first: scripts/start.sh"

C=(curl -sk)
JSON=(-H "Content-Type: application/json")
ISA=(-u "$ADMIN_USER:$ADMIN_PASS")
q() { jq -rn --arg v "$1" '$v|@uri'; }

TOOLS=(atlassianUserInfo getAccessibleAtlassianResources getVisibleJiraProjects getJiraIssue
       searchJiraIssuesUsingJql getJiraIssueRemoteIssueLinks searchBitbucketRepositories
       listBitbucketPullRequests getBitbucketFileContent)
JIRA_TOOLS="getVisibleJiraProjects getJiraIssue searchJiraIssuesUsingJql getJiraIssueRemoteIssueLinks"
BITBUCKET_TOOLS="searchBitbucketRepositories listBitbucketPullRequests getBitbucketFileContent"
SCOPES_JSON='[
  {"name": "jira:read", "displayName": "Read Jira", "description": "Jira tools of the Atlassian MCP server"},
  {"name": "bitbucket:read", "displayName": "Read Bitbucket", "description": "Bitbucket tools of the Atlassian MCP server"}]'

is_app_id() {   # is_app_id <name>
  "${C[@]}" "${ISA[@]}" "$IS_BASE/api/server/v1/applications?filter=$(q "name eq $1")" | jq -r '.applications[0].id // empty'
}
is_create_app() {   # is_create_app <json body>
  local res
  res=$("${C[@]}" "${ISA[@]}" "${JSON[@]}" -w '\n%{http_code}' -d "$1" "$IS_BASE/api/server/v1/applications")
  [[ "${res##*$'\n'}" == "201" ]] || die "could not create the IS application: ${res%$'\n'*}"
}

# ========================================================================================
#  WSO2 IS
# ========================================================================================
say "IS 1. User $DEMO_USER"
user_id=$("${C[@]}" "${ISA[@]}" "$IS_BASE/scim2/Users?filter=userName+eq+$DEMO_USER" | jq -r '.Resources[0].id // empty')
if [[ -n "$user_id" ]]; then info "exists"
else
  res=$("${C[@]}" "${ISA[@]}" "${JSON[@]}" "$IS_BASE/scim2/Users" -d "$(jq -nc \
    --arg u "$DEMO_USER" --arg p "$DEMO_PASS" --arg e "$DEMO_EMAIL" \
    '{schemas: [], userName: $u, password: $p, name: {givenName: "Dana", familyName: "Whitfield"},
      emails: [{primary: true, value: $e}]}')")
  user_id=$(jq -r '.id // empty' <<<"$res"); [[ -n "$user_id" ]] || die "could not create $DEMO_USER: $res"
  info "created ($DEMO_EMAIL)"
fi

say "IS 2. App \"MCP Gateway\" ($GATEWAY_CLIENT_ID)"
gw_app=$(is_app_id "MCP Gateway")
if [[ -n "$gw_app" ]]; then info "exists"
else
  is_create_app "$(jq -nc --arg c "$GATEWAY_CLIENT_ID" '{
    name: "MCP Gateway",
    description: "The API Manager gateway: exchanges users ID tokens for ID-JAGs",
    inboundProtocolConfiguration: {oidc: {clientId: $c, publicClient: false,
      grantTypes: ["urn:ietf:params:oauth:grant-type:token-exchange"]}}}')"
  gw_app=$(is_app_id "MCP Gateway"); info "created"
fi
gw_secret=$("${C[@]}" "${ISA[@]}" "$IS_BASE/api/server/v1/applications/$gw_app/inbound-protocols/oidc" | jq -r .clientSecret)
umask 077
printf 'GATEWAY_CLIENT_SECRET=%s\n' "$gw_secret" > "$STATE"
# A Postman environment for postman/id-jag-walkthrough (its folder 4 acts as the gateway).
jq -n --arg s "$gw_secret" '{name: "ID-JAG demo (local)", _postman_variable_scope: "environment",
  values: [{key: "gateway_client_secret", value: $s, type: "secret", enabled: true}]}' > "$SETUP/postman-environment.json"
umask 022
info "secret saved to setup/.state.env and setup/postman-environment.json"

say "IS 3. App \"GitHub Copilot VS Code\" ($COPILOT_CLIENT_ID)"
# IS removes the port from loopback redirect URIs before matching, hence the optional port.
copilot_oidc=$(jq -nc --arg c "$COPILOT_CLIENT_ID" --arg gw "$GATEWAY_CLIENT_ID" '{
  clientId: $c, publicClient: true,
  grantTypes: ["authorization_code", "refresh_token"],
  callbackURLs: ["regexp=(http://127\\.0\\.0\\.1(:[0-9]+)?/|https://vscode\\.dev/redirect|https://insiders\\.vscode\\.dev/redirect)"],
  pkce: {mandatory: true, supportPlainTransformAlgorithm: false},
  accessToken: {type: "JWT", userAccessTokenExpiryInSeconds: 3600, applicationAccessTokenExpiryInSeconds: 3600},
  idToken: {expiryInSeconds: 3600, audience: [$gw]}}')
copilot_app=$(is_app_id "GitHub Copilot VS Code")
if [[ -n "$copilot_app" ]]; then info "exists"
else
  is_create_app "$(jq -nc --argjson o "$copilot_oidc" '{
    name: "GitHub Copilot VS Code",
    description: "GitHub Copilot in VS Code, signing in for the MCP gateway",
    inboundProtocolConfiguration: {oidc: $o},
    advancedConfigurations: {skipLoginConsent: true, skipLogoutConsent: true}}')"
  copilot_app=$(is_app_id "GitHub Copilot VS Code"); info "created"
fi
copilot_secret=$("${C[@]}" "${ISA[@]}" "$IS_BASE/api/server/v1/applications/$copilot_app/inbound-protocols/oidc" | jq -r '.clientSecret // ""')

say "IS 4. Tool scopes, granted by role"
api_res=$("${C[@]}" "${ISA[@]}" "$IS_BASE/api/server/v1/api-resources?filter=$(q "identifier eq $MCP_URL")" | jq -r '.apiResources[0].id // empty')
if [[ -z "$api_res" ]]; then
  res=$("${C[@]}" "${ISA[@]}" "${JSON[@]}" "$IS_BASE/api/server/v1/api-resources" -d "$(jq -nc \
    --arg i "$MCP_URL" --argjson s "$SCOPES_JSON" \
    '{name: "Atlassian MCP tools", identifier: $i, requiresAuthorization: true, scopes: $s,
      description: "Scopes API Manager checks on the Atlassian MCP server tools"}')")
  api_res=$(jq -r '.id // empty' <<<"$res"); [[ -n "$api_res" ]] || die "could not create the API resource: $res"
fi
info "API resource \"Atlassian MCP tools\": jira:read, bitbucket:read"
if [[ "$("${C[@]}" "${ISA[@]}" "$IS_BASE/api/server/v1/applications/$copilot_app/authorized-apis" \
      | jq -r --arg a "$api_res" '[.[]? | select(.id == $a)] | length')" == "0" ]]; then
  "${C[@]}" "${ISA[@]}" "${JSON[@]}" -o /dev/null "$IS_BASE/api/server/v1/applications/$copilot_app/authorized-apis" \
    -d "$(jq -nc --arg a "$api_res" '{id: $a, policyIdentifier: "RBAC", scopes: ["jira:read", "bitbucket:read"]}')"
fi
info "authorized for Copilot's app, role-based"
role_id=$("${C[@]}" "${ISA[@]}" "$IS_BASE/scim2/v2/Roles?filter=$(q "displayName eq atlassian-tools-user")" \
  | jq -r --arg a "$copilot_app" '.Resources[]? | select(.audience.value == $a) | .id' | head -1)
if [[ -z "$role_id" ]]; then
  res=$("${C[@]}" "${ISA[@]}" -H "Content-Type: application/scim+json" "$IS_BASE/scim2/v2/Roles" -d "$(jq -nc \
    --arg a "$copilot_app" --arg u "$user_id" '{
      schemas: ["urn:ietf:params:scim:schemas:extension:2.0:Role"], displayName: "atlassian-tools-user",
      audience: {type: "application", value: $a},
      permissions: [{value: "jira:read"}, {value: "bitbucket:read"}], users: [{value: $u}]}')")
  jq -e .id >/dev/null <<<"$res" || die "could not create the role: $res"
fi
info "role atlassian-tools-user: jira:read, bitbucket:read; assigned to $DEMO_USER"

# ========================================================================================
#  API Manager
# ========================================================================================
tok=$(apim_token "apim:admin apim:api_view apim:api_create apim:api_manage apim:api_publish \
apim:mcp_server_view apim:mcp_server_create apim:mcp_server_manage apim:mcp_server_publish \
apim:common_operation_policy_view apim:common_operation_policy_manage apim:gateway_policy_view \
apim:gateway_policy_manage apim:subscribe apim:app_manage apim:sub_manage")
[[ -n "$tok" ]] || die "could not get an API Manager admin token"
AUTH=(-H "Authorization: Bearer $tok")
PUB="$APIM/api/am/publisher/v4"; DEV="$APIM/api/am/devportal/v3"; ADM="$APIM/api/am/admin/v4"

say "APIM 5. Key Manager WSO2IS"
if "${C[@]}" "${AUTH[@]}" "$ADM/key-managers" | jq -e '.list[] | select(.name == "WSO2IS")' >/dev/null; then info "exists"
else
  res=$("${C[@]}" "${AUTH[@]}" "${JSON[@]}" "$ADM/key-managers" -d "$(jq -nc --arg b "$IS_BASE" --arg u "$ADMIN_USER" --arg p "$ADMIN_PASS" '{
    name: "WSO2IS", displayName: "WSO2 Identity Server", type: "WSO2-IS-7",
    description: "Users sign in at WSO2 IS; IS issues their access tokens and ID tokens, and mints ID-JAGs.",
    wellKnownEndpoint: ($b + "/oauth2/token/.well-known/openid-configuration"),
    issuer: ($b + "/oauth2/token"), tokenEndpoint: ($b + "/oauth2/token"), displayTokenEndpoint: ($b + "/oauth2/token"),
    authorizeEndpoint: ($b + "/oauth2/authorize"), revokeEndpoint: ($b + "/oauth2/revoke"),
    displayRevokeEndpoint: ($b + "/oauth2/revoke"), introspectionEndpoint: ($b + "/oauth2/introspect"),
    userInfoEndpoint: ($b + "/oauth2/userinfo"),
    clientRegistrationEndpoint: ($b + "/api/identity/oauth2/dcr/v1.1/register"),
    scopeManagementEndpoint: ($b + "/api/server/v1/api-resources"),
    certificates: {type: "JWKS", value: ($b + "/oauth2/jwks")},
    enabled: true, enableTokenGeneration: true, enableMapOAuthConsumerApps: true,
    enableOAuthAppCreation: true, enableSelfValidationJWT: true, tokenType: "DIRECT",
    availableGrantTypes: ["authorization_code", "refresh_token"],
    additionalProperties: {identity_server_base_url: $b,
      api_resource_management_endpoint: ($b + "/api/server/v1/api-resources"),
      is7_roles_endpoint: ($b + "/scim2/v2/Roles"), Username: $u, Password: $p, self_validate_jwt: true}}')")
  jq -e .id >/dev/null <<<"$res" || die "could not create the Key Manager: $res"
  info "created"
fi

say "APIM 6. MCP server $MCP_SERVER (upstream: the mock)"
server_id=$("${C[@]}" "${AUTH[@]}" "$PUB/mcp-servers?limit=100" | jq -r --arg n "$MCP_SERVER" '.list[] | select(.name == $n) | .id // empty')
if [[ -n "$server_id" ]]; then info "exists"
else
  # Discovery: APIM lists the upstream's tools (anonymous on the mock, as on Atlassian's own).
  val=$("${C[@]}" "${AUTH[@]}" "${JSON[@]}" "$PUB/mcp-servers/validate-mcp-server" -d "{\"url\":\"$MOCK\",\"securityInfo\":{\"isSecure\":false}}")
  jq -e '.isValid == true' >/dev/null <<<"$val" || die "APIM could not discover the mock's tools: $val"
  # name/context/version and the tool list go inside additionalProperties; the endpoint must be
  # given here, at creation, where it lands on the server's backend. No endpoint security: the
  # gateway policy sets the upstream Authorization header itself.
  body=$(jq -r '.content' <<<"$val" | jq -c --arg n "$MCP_SERVER" --arg ctx "$MCP_CONTEXT" --arg url "$MOCK" \
    --argjson pick "$(printf '%s\n' "${TOOLS[@]}" | jq -R . | jq -sc .)" '
    [.tools[] | select(.name as $t | $pick | index($t))] as $tools
    | {url: $url, securityInfo: {isSecure: false}, additionalProperties: {
        name: $n, displayName: "Atlassian Rovo", context: $ctx, version: "v1",
        description: "Read-only Jira and Bitbucket tools for AI assistants, through the WSO2 gateway",
        endpointConfig: {endpoint_type: "http", production_endpoints: {url: $url}, sandbox_endpoints: {url: $url}},
        operations: [$tools[] | {target: .name, feature: "TOOL", authType: "Application & Application User",
          throttlingPolicy: "Unlimited", scopes: [], description: (.description // ""),
          schemaDefinition: (.inputSchema // {} | tojson),
          backendOperationMapping: {backendOperation: {target: .name, verb: "TOOL"}}}],
        policies: ["Unlimited"], transport: ["http", "https"]}}')
  res=$("${C[@]}" "${AUTH[@]}" "${JSON[@]}" "$PUB/mcp-servers/generate-from-mcp-server" -d "$body")
  server_id=$(jq -r '.id // empty' <<<"$res"); [[ -n "$server_id" ]] || die "could not create the MCP server: $res"
  # Per-tool scopes.
  "${C[@]}" "${AUTH[@]}" "$PUB/mcp-servers/$server_id" | jq -c --arg jira "$JIRA_TOOLS" --arg bb "$BITBUCKET_TOOLS" '
    ($jira | split(" ")) as $j | ($bb | split(" ")) as $b
    | .scopes = [{scope: {name: "jira:read", displayName: "jira:read", description: "Read Jira", bindings: []}, shared: false},
                 {scope: {name: "bitbucket:read", displayName: "bitbucket:read", description: "Read Bitbucket", bindings: []}, shared: false}]
    | .operations |= map(.target as $t | .scopes = (if ($j | index($t)) then ["jira:read"]
                                                    elif ($b | index($t)) then ["bitbucket:read"] else [] end))' \
    > "$SETUP/logs/mcp-server.json"
  res=$("${C[@]}" "${AUTH[@]}" "${JSON[@]}" -X PUT "$PUB/mcp-servers/$server_id" -d @"$SETUP/logs/mcp-server.json")
  jq -e .id >/dev/null <<<"$res" || die "could not set the tool scopes: $res"
  rid=$("${C[@]}" "${AUTH[@]}" "${JSON[@]}" "$PUB/mcp-servers/$server_id/revisions" -d '{"description":"initial"}' | jq -r .id)
  "${C[@]}" "${AUTH[@]}" "${JSON[@]}" -o /dev/null "$PUB/mcp-servers/$server_id/deploy-revision?revisionId=$rid" \
    -d '[{"name":"Default","vhost":"localhost","displayOnDevportal":true}]'
  "${C[@]}" "${AUTH[@]}" -o /dev/null -X POST "$PUB/mcp-servers/change-lifecycle?action=Publish&mcpServerId=$server_id"
  info "created with ${#TOOLS[@]} tools, scopes jira:read and bitbucket:read, deployed and published"
fi
for _ in $(seq 1 30); do   # the gateway pulls the deployment asynchronously
  n=$("${C[@]}" "$MCP_URL" "${JSON[@]}" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | jq '.result.tools | length' 2>/dev/null || true)
  [[ "$n" == "${#TOOLS[@]}" ]] && break; sleep 2
done
info "gateway lists ${n:-0} tools at $MCP_URL"

say "APIM 7. Custom policies"
policy_id() {
  "${C[@]}" "${AUTH[@]}" "$PUB/operation-policies?limit=200" | jq -r --arg n "$1" '.list[] | select(.name == $n) | .id // empty'
}
for p in idJagTokenExchange idpProxy; do
  if [[ -z "$(policy_id $p)" ]]; then
    res=$("${C[@]}" "${AUTH[@]}" "$PUB/operation-policies" \
      -F "policySpecFile=@$REPO/code/apim-idjag-policy/policy/$p.json;type=application/json" \
      -F "synapsePolicyDefinitionFile=@$REPO/code/apim-idjag-policy/policy/$p.j2")
    jq -e .id >/dev/null <<<"$res" || die "could not upload $p: $res"
  fi
  info "$p"
done

say "APIM 8. Gateway policy: ID-JAG token exchange on every MCP tools/call"
params=$(jq -nc --arg is "$IS_BASE/oauth2/token" --arg cid "$GATEWAY_CLIENT_ID" --arg cs "$gw_secret" \
  --arg aud "$MOCK" --arg as "$MOCK/oauth/token" --arg acs "$ATLASSIAN_CLIENT_SECRET" \
  --arg signin "$GATEWAY/idp/oauth2/token" '{
    idpTokenEndpoint: $is, idpClientId: $cid, idpClientSecret: $cs, audience: $aud, idpScopes: "",
    resourceAsTokenEndpoint: $as, resourceAsClientId: $cid, resourceAsClientSecret: $acs, resourceAsScopes: "",
    idTokenHeader: "X-ID-Token", timeoutMillis: "10000", tlsInsecureSkipVerify: "false",
    authorizationServer: $signin, scopesSupported: "openid jira:read bitbucket:read"}')
mapping=$(jq -nc --arg pid "$(policy_id idJagTokenExchange)" --argjson p "$params" '{
  displayName: "idjag_token_exchange", description: "ID-JAG token exchange on MCP tools/call",
  policyMapping: {request: [{policyName: "idJagTokenExchange", policyVersion: "v1", policyId: $pid, parameters: $p}],
                  response: [], fault: []}}')
mid=$("${C[@]}" "${AUTH[@]}" "$PUB/gateway-policies" | jq -r '.list[]? | select(.displayName == "idjag_token_exchange") | .id // empty')
if [[ -z "$mid" ]]; then
  mid=$("${C[@]}" "${AUTH[@]}" "${JSON[@]}" "$PUB/gateway-policies" -d "$mapping" | jq -r '.id // empty')
  [[ -n "$mid" ]] || die "could not create the gateway policy"
else
  # Updated in place: a deleted gateway policy keeps running until APIM restarts.
  "${C[@]}" "${AUTH[@]}" "${JSON[@]}" -o /dev/null -X PUT "$PUB/gateway-policies/$mid" -d "$mapping"
fi
"${C[@]}" "${AUTH[@]}" "${JSON[@]}" -o /dev/null "$PUB/gateway-policies/$mid/deploy" \
  -d "[{\"mappingUUID\":\"$mid\",\"gatewayLabel\":\"Default\",\"gatewayDeployment\":true}]"
info "deployed to the Default gateway"

say "APIM 9. REST API /idp (sign-in relay to WSO2 IS)"
idp_id=$("${C[@]}" "${AUTH[@]}" "$PUB/apis?query=name:IdpProxy" | jq -r '.list[]? | select(.name == "IdpProxy") | .id // empty')
if [[ -n "$idp_id" ]]; then info "exists"
else
  # Two resources at IS's own paths, without APIM authentication (the client authenticates at IS),
  # each with idpProxy on its response flow.
  body=$(jq -nc --arg is "$IS_BASE" --arg pid "$(policy_id idpProxy)" --arg pub "$GATEWAY/idp" '
    {policyName: "idpProxy", policyVersion: "v1", policyId: $pid, parameters: {publicBaseUrl: $pub}} as $relay
    | {verb: "GET", authType: "None", throttlingPolicy: "Unlimited",
       operationPolicies: {request: [], response: [$relay], fault: []}} as $op
    | {name: "IdpProxy", context: "/idp", version: "v1", isDefaultVersion: true, type: "HTTP",
       description: "Relays WSO2 IS sign-in metadata and token endpoint for MCP clients; keeps each user'"'"'s ID token",
       transport: ["https"], policies: ["Unlimited"],
       endpointConfig: {endpoint_type: "http", production_endpoints: {url: $is}, sandbox_endpoints: {url: $is}},
       operations: [($op + {target: "/oauth2/token/.well-known/openid-configuration"}),
                    ($op + {target: "/oauth2/token", verb: "POST"})]}')
  idp_id=$("${C[@]}" "${AUTH[@]}" "${JSON[@]}" "$PUB/apis" -d "$body" | jq -r '.id // empty')
  [[ -n "$idp_id" ]] || die "could not create the /idp API"
  rid=$("${C[@]}" "${AUTH[@]}" "${JSON[@]}" "$PUB/apis/$idp_id/revisions" -d '{"description":"initial"}' | jq -r .id)
  "${C[@]}" "${AUTH[@]}" "${JSON[@]}" -o /dev/null "$PUB/apis/$idp_id/deploy-revision?revisionId=$rid" \
    -d '[{"name":"Default","vhost":"localhost","displayOnDevportal":false}]'
  "${C[@]}" "${AUTH[@]}" -o /dev/null -X POST "$PUB/apis/change-lifecycle?apiId=$idp_id&action=Publish"
  info "created, deployed and published"
fi
for _ in $(seq 1 30); do   # the gateway pulls the deployment asynchronously
  [[ "$("${C[@]}" -o /dev/null -w '%{http_code}' "$GATEWAY/idp/oauth2/token/.well-known/openid-configuration")" == "200" ]] && break
  sleep 2
done
info "gateway answers at $GATEWAY/idp"

say "APIM 10. Application CopilotVSCode"
app_id=$("${C[@]}" "${AUTH[@]}" "$DEV/applications?query=CopilotVSCode" | jq -r '.list[]? | select(.name == "CopilotVSCode") | .applicationId // empty')
if [[ -z "$app_id" ]]; then
  app_id=$("${C[@]}" "${AUTH[@]}" "${JSON[@]}" "$DEV/applications" \
    -d '{"name":"CopilotVSCode","throttlingPolicy":"Unlimited","description":"GitHub Copilot in VS Code (IS client vscode-copilot)"}' \
    | jq -r '.applicationId // empty')
  [[ -n "$app_id" ]] || die "could not create the application"
fi
if [[ "$("${C[@]}" "${AUTH[@]}" "$DEV/subscriptions?applicationId=$app_id" | jq -r --arg s "$server_id" '[.list[]? | select(.apiId == $s)] | length')" == "0" ]]; then
  "${C[@]}" "${AUTH[@]}" "${JSON[@]}" -o /dev/null "$DEV/subscriptions" \
    -d "$(jq -nc --arg a "$server_id" --arg p "$app_id" '{apiId: $a, applicationId: $p, throttlingPolicy: "Unlimited"}')"
fi
if [[ "$("${C[@]}" "${AUTH[@]}" "$DEV/applications/$app_id/oauth-keys" | jq -r '.list[]? | select(.keyManager == "WSO2IS") | .consumerKey')" != "$COPILOT_CLIENT_ID" ]]; then
  for _ in $(seq 1 15); do   # a new Key Manager registers asynchronously
    res=$("${C[@]}" "${AUTH[@]}" "${JSON[@]}" "$DEV/applications/$app_id/map-keys" -d "$(jq -nc \
      --arg k "$COPILOT_CLIENT_ID" --arg s "$copilot_secret" \
      '{consumerKey: $k, consumerSecret: $s, keyType: "PRODUCTION", keyManager: "WSO2IS"}')")
    grep -q "Key Manager not Registered" <<<"$res" || break; sleep 2
  done
  [[ "$(jq -r '.consumerKey // empty' <<<"$res")" == "$COPILOT_CLIENT_ID" ]] || die "could not map the keys: $res"
fi
info "subscribed to $MCP_SERVER; keys: $COPILOT_CLIENT_ID (Key Manager WSO2IS)"

say "Done. Next: scripts/verify.sh, then VS Code (README, step 5)"
