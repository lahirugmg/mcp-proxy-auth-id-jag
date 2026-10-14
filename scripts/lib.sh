# shellcheck shell=bash
# lib.sh — settings and helpers shared by the scripts. Sourced, not run.

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SETUP="$REPO/setup"

# The unpacked products (scripts/install.sh unzips them here); empty until then.
IS_HOME=""; APIM_HOME=""
[[ -d "$SETUP/wso2is-7.3.0" ]] && IS_HOME="$SETUP/wso2is-7.3.0"
[[ -d "$SETUP/wso2am-4.6.0" ]] && APIM_HOME="$SETUP/wso2am-4.6.0"

# Where everything listens. IS runs with port offset 1 so it does not clash with APIM.
IS_BASE="https://localhost:9444"
APIM="https://localhost:9443"
GATEWAY="https://localhost:8243"
MOCK="http://localhost:9500"

# Demo identities (local only).
ADMIN_USER="admin"; ADMIN_PASS="admin"
DEMO_USER="dana"; DEMO_EMAIL="dana@example.com"; DEMO_PASS="Demo@12345"
GATEWAY_CLIENT_ID="wso2-mcp-gateway"                       # the gateway's client at IS and at Atlassian
ATLASSIAN_CLIENT_SECRET="wso2-gateway-atlassian-secret-abc123"  # the gateway's secret at the Atlassian mock
COPILOT_CLIENT_ID="vscode-copilot"                         # GitHub Copilot's public client at IS
MCP_SERVER="AtlassianRovo"
MCP_CONTEXT="/atlassian-rovo"
MCP_URL="$GATEWAY$MCP_CONTEXT/v1/mcp"

# Secrets created at configure time (gateway client secret at IS).
STATE="$SETUP/.state.env"

say()  { printf '\n==> %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

need() { for c in "$@"; do command -v "$c" >/dev/null 2>&1 || die "'$c' is required"; done; }

# Version of a bundled jar: jar_version <dir> <name prefix up to the underscore>
#   jar_version "$IS_HOME/repository/components/plugins" org.wso2.carbon.identity.oauth  -> 7.4.99.34
jar_version() {
  local f
  f=$(ls "$1/$2"_*.jar 2>/dev/null | head -1)
  [[ -n "$f" ]] || die "no $2_*.jar in $1"
  f=${f##*/}; f=${f#"$2"_}; echo "${f%.jar}"
}

is_up()      { curl -sk -o /dev/null -f "$IS_BASE/api/health-check/v1.0/health"; }
apim_up()    { curl -sk -o /dev/null -f "$APIM/services/Version"; }
gateway_up() { [[ "$(curl -sk -o /dev/null -w '%{http_code}' "$GATEWAY/")" != "000" ]]; }
mock_up()    { curl -s -o /dev/null -f "$MOCK/healthz"; }

wait_for() {   # wait_for <check function> <seconds> <name>
  local i
  for ((i = 0; i < $2; i += 3)); do "$1" && return 0; sleep 3; done
  die "$3 did not come up within $2 s"
}

# An APIM admin token with the given scopes, from one named provisioning client.
apim_token() {
  local dcr ck cs
  dcr=$(curl -sk -u "$ADMIN_USER:$ADMIN_PASS" -H "Content-Type: application/json" \
    -d '{"callbackUrl":"http://localhost","clientName":"idjag_demo_provisioner","owner":"'"$ADMIN_USER"'","grantType":"password refresh_token","saasApp":true}' \
    "$APIM/client-registration/v0.17/register")
  ck=$(jq -r '.clientId // empty' <<<"$dcr"); cs=$(jq -r '.clientSecret // empty' <<<"$dcr")
  [[ -n "$ck" ]] || die "APIM client registration failed: $dcr"
  curl -sk -u "$ck:$cs" "$APIM/oauth2/token" -d grant_type=password \
    -d "username=$ADMIN_USER" --data-urlencode "password=$ADMIN_PASS" \
    --data-urlencode "scope=$1" | jq -r '.access_token // empty'
}
