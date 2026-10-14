#!/usr/bin/env bash
#
# install.sh — one-time, offline preparation. Run it with the servers stopped.
#
#   1. Unzips the WSO2 IS 7.3.0 and API Manager 4.6.0 packs found in setup/.
#   2. WSO2 IS: port offset 1 (9444), the ID-JAG grant built against the pack's own
#      jars and dropped in, its identity.xml.j2 block, and its deployment.toml keys.
#   3. API Manager: the gateway mediators built against the pack's own jars, a log
#      category for them, trust in IS's certificate, and a TLS certificate from a
#      local development CA (VS Code rejects APIM's stock self-signed one).
#   4. The Atlassian mock: virtualenv and tests.
#
# Safe to re-run: each step skips work already done.

set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

need java mvn python3 jq curl openssl keytool unzip
java_major=$(java -version 2>&1 | sed -nE 's/.*version "([0-9]+).*/\1/p' | head -1)
[[ "${java_major:-0}" -ge 17 ]] || die "JDK 17 or newer is required (found ${java_major:-none})"
is_up && die "WSO2 IS is running: stop it first (scripts/stop.sh)"
apim_up && die "API Manager is running: stop it first (scripts/stop.sh)"

# --- 1. Unpack -----------------------------------------------------------------------
say "Products"
unpack() {   # unpack <zip glob> <directory>
  local zip
  if [[ -d "$SETUP/$2" ]]; then info "$2 already unpacked"; return; fi
  zip=$(ls "$SETUP"/$1 2>/dev/null | head -1)
  [[ -n "$zip" ]] || die "put the $2 zip into setup/ (see README: Prerequisites)"
  unzip -q "$zip" -d "$SETUP"
  info "unpacked $(basename "$zip")"
}
unpack 'wso2is-7.3.0*.zip' wso2is-7.3.0
unpack 'wso2am-4.6.0*.zip' wso2am-4.6.0
IS_HOME="$SETUP/wso2is-7.3.0"; APIM_HOME="$SETUP/wso2am-4.6.0"
mkdir -p "$SETUP/backups" "$SETUP/certs" "$SETUP/logs"

backup() { [[ -f "$SETUP/backups/$2" ]] || cp "$1" "$SETUP/backups/$2"; }

# --- 2. WSO2 Identity Server -----------------------------------------------------------
IS_TOML="$IS_HOME/repository/conf/deployment.toml"
IS_PLUGINS="$IS_HOME/repository/components/plugins"
IDENTITY_J2="$IS_HOME/repository/resources/conf/templates/repository/conf/identity/identity.xml.j2"
backup "$IS_TOML" is-deployment.toml
backup "$IDENTITY_J2" is-identity.xml.j2

say "WSO2 IS: port offset 1 (9444)"
if grep -q '^offset *= *"1"' "$IS_TOML"; then info "already set"
else
  python3 - "$IS_TOML" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
s = s.replace("[server]\n", '[server]\noffset = "1"\n', 1)
open(p, "w").write(s)
PY
  info "set"
fi

say "WSO2 IS: ID-JAG grant (code/idjag-grant)"
v() { jar_version "$IS_PLUGINS" "$1"; }
( cd "$REPO/code/idjag-grant" && mvn -q -B clean package \
    -Dis.home="$IS_HOME" \
    -Didentity.oauth.version="$(v org.wso2.carbon.identity.oauth)" \
    -Didentity.oauth.common.version="$(v org.wso2.carbon.identity.oauth.common)" \
    -Dtoken.exchange.version="$(v org.wso2.carbon.identity.oauth2.grant.token.exchange)" \
    -Didentity.framework.version="$(v org.wso2.carbon.identity.application.common)" \
    -Didentity.framework.auth.version="$(v org.wso2.carbon.identity.application.authentication.framework)" \
    -Didentity.framework.core.version="$(v org.wso2.carbon.identity.core)" \
    -Didentity.framework.base.version="$(v org.wso2.carbon.identity.base)" \
    -Dcarbon.user.core.version="$(v org.wso2.carbon.user.core)" \
    -Dcarbon.user.api.version="$(v org.wso2.carbon.user.api)" \
    -Dcarbon.utils.version="$(v org.wso2.carbon.utils)" \
    -Dnimbusds.version="$(v nimbus-jose-jwt)" \
    -Dcommons.lang.version="$(v commons-lang)" )
grant_jar=$(ls "$REPO"/code/idjag-grant/target/org.wso2.custom.identity.oauth2.grant.tokenexchange.idjag-*.jar)
rm -f "$IS_HOME"/repository/components/dropins/org.wso2.custom.identity.oauth2.grant.tokenexchange.idjag-*.jar
cp "$grant_jar" "$IS_HOME/repository/components/dropins/"
info "built and copied to repository/components/dropins"

# The grant reads its settings from identity.xml, which IS renders from this template.
if grep -q '<IDJAG>' "$IDENTITY_J2"; then info "identity.xml.j2 already has the <IDJAG> block"
else
  python3 - "$IDENTITY_J2" "$REPO/code/idjag-grant/conf/identity-xml-idjag-block.xml" <<'PY'
import sys
tpl, block = sys.argv[1], open(sys.argv[2]).read()
s = open(tpl).read()
anchor = "        </SupportedGrantTypes>\n"
assert s.count(anchor) == 1, "expected one </SupportedGrantTypes> in identity.xml.j2"
open(tpl, "w").write(s.replace(anchor, anchor + block))
PY
  info "identity.xml.j2: <IDJAG> block added"
fi

if grep -q 'idjag.IdJagGrantHandler' "$IS_TOML"; then info "deployment.toml already configures the grant"
else
  cat >> "$IS_TOML" <<'EOF'

# ID-JAG: the token exchange grant also issues ID-JAGs
# (requested_token_type=urn:ietf:params:oauth:token-type:id-jag). Added by scripts/install.sh.
[oauth.grant_type.token_exchange]
enable = true
grant_handler = "org.wso2.custom.identity.oauth2.grant.idjag.IdJagGrantHandler"
grant_validator = "org.wso2.carbon.identity.oauth2.grant.token.exchange.TokenExchangeGrantValidator"
allow_refresh_tokens = false

[oauth.idjag]
# The ID-JAG "sub" is the user's email: the identifier Atlassian knows people by.
subject_claim_uri = "http://wso2.org/claims/emailaddress"
require_subject_claim = true
# ID-JAG lifetime in seconds.
validity_period = 300
# Reject subject tokens issued longer ago than this many minutes.
iat_validity_period = 60
# Only an ID token may be the subject token, never a refresh token.
allow_refresh_token_subject_token = false
EOF
  info "deployment.toml: grant handler and [oauth.idjag] added"
fi

# --- 3. API Manager ---------------------------------------------------------------------
APIM_TOML="$APIM_HOME/repository/conf/deployment.toml"
APIM_PLUGINS="$APIM_HOME/repository/components/plugins"
APIM_SECURITY="$APIM_HOME/repository/resources/security"
LOG4J="$APIM_HOME/repository/conf/log4j2.properties"
backup "$APIM_TOML" apim-deployment.toml
backup "$LOG4J" apim-log4j2.properties
backup "$APIM_SECURITY/client-truststore.jks" apim-client-truststore.jks

say "API Manager: gateway mediators (code/apim-idjag-policy)"
a() { jar_version "$APIM_PLUGINS" "$1"; }
( cd "$REPO/code/apim-idjag-policy" && mvn -q -B clean package \
    -Dapim.home="$APIM_HOME" \
    -Dv.gateway="$(a org.wso2.carbon.apimgt.gateway)" \
    -Dv.synapse.core="$(a synapse-core)" \
    -Dv.synapse.commons="$(a synapse-commons)" \
    -Dv.synapse.transport="$(a synapse-nhttp-transport)" \
    -Dv.axis2="$(a axis2)" \
    -Dv.axiom="$(a axiom)" \
    -Dv.paxlogging="$(a org.ops4j.pax.logging.pax-logging-api)" \
    -Dv.gson="$(a com.google.gson)" )
cp "$REPO"/code/apim-idjag-policy/target/idjag-gateway-policy-*.jar "$APIM_HOME/repository/components/lib/"
info "built (unit tests passed) and copied to repository/components/lib"

# APIM's root logger is at ERROR; give the mediators' package its own INFO logger.
if grep -q '^logger.idjag.name' "$LOG4J"; then info "log category already present"
else
  sed -i.bak -E 's/^(loggers = .*)$/\1, idjag/' "$LOG4J" && rm -f "$LOG4J.bak"
  printf '\n# ID-JAG gateway mediators (scripts/install.sh)\nlogger.idjag.name = org.wso2.mcpgov\nlogger.idjag.level = INFO\n' >> "$LOG4J"
  info "log category org.wso2.mcpgov at INFO"
fi

say "API Manager: trust WSO2 IS's TLS certificate"
TRUSTSTORE="$APIM_SECURITY/client-truststore.jks"
if keytool -list -keystore "$TRUSTSTORE" -storepass wso2carbon -alias wso2is-localhost >/dev/null 2>&1; then
  info "already trusted"
else
  keytool -exportcert -rfc -alias wso2carbon -storetype PKCS12 -storepass wso2carbon \
    -keystore "$IS_HOME/repository/resources/security/wso2carbon.p12" > "$SETUP/certs/wso2is-localhost.pem"
  keytool -importcert -noprompt -alias wso2is-localhost -file "$SETUP/certs/wso2is-localhost.pem" \
    -keystore "$TRUSTSTORE" -storepass wso2carbon >/dev/null 2>&1
  info "IS certificate imported into client-truststore.jks"
fi

say "API Manager: TLS certificate from a local development CA"
CA_KEY="$SETUP/certs/dev-ca.key"; CA_PEM="$SETUP/certs/dev-ca.pem"
if [[ ! -f "$CA_PEM" ]]; then
  openssl req -x509 -newkey rsa:3072 -sha256 -days 825 -nodes -keyout "$CA_KEY" -out "$CA_PEM" \
    -subj "/CN=ID-JAG Demo Local Dev CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  chmod 600 "$CA_KEY"
  info "created setup/certs/dev-ca.pem"
fi
if [[ ! -f "$APIM_SECURITY/gateway-tls.jks" ]]; then
  ext=$(mktemp)
  printf '%s\n' "basicConstraints=critical,CA:FALSE" "keyUsage=critical,digitalSignature,keyEncipherment" \
    "extendedKeyUsage=serverAuth" "subjectAltName=DNS:localhost,IP:127.0.0.1" > "$ext"
  openssl req -newkey rsa:2048 -sha256 -nodes -keyout "$SETUP/certs/localhost.key" -subj "/CN=localhost" 2>/dev/null \
    | openssl x509 -req -sha256 -days 397 -CA "$CA_PEM" -CAkey "$CA_KEY" -CAcreateserial \
      -extfile "$ext" -out "$SETUP/certs/localhost.pem" 2>/dev/null
  openssl pkcs12 -export -name gateway-tls -inkey "$SETUP/certs/localhost.key" -in "$SETUP/certs/localhost.pem" \
    -certfile "$CA_PEM" -passout pass:wso2carbon -out "$SETUP/certs/localhost.p12"
  keytool -importkeystore -noprompt -srckeystore "$SETUP/certs/localhost.p12" -srcstoretype PKCS12 \
    -srcstorepass wso2carbon -destkeystore "$APIM_SECURITY/gateway-tls.jks" -deststoretype JKS \
    -deststorepass wso2carbon -destkeypass wso2carbon >/dev/null 2>&1
  rm -f "$ext"
  info "issued a localhost certificate; keystore repository/resources/security/gateway-tls.jks"
fi
# The gateway's HTTPS listener (8243) always uses [keystore.tls]; the console (9443) shares it.
# APIM's signing keys ([keystore.primary]) are untouched.
python3 - "$APIM_TOML" <<'PY'
import re, sys
p = sys.argv[1]; s = open(p).read()
def fix(m):
    body = re.sub(r'(?m)^file_name\s*=.*$', 'file_name = "gateway-tls.jks"', m.group(0))
    return re.sub(r'(?m)^alias\s*=.*$', 'alias = "gateway-tls"', body)
s2 = re.sub(r'(?ms)^\[keystore\.tls\]\n.*?(?=^\[|\Z)', fix, s, count=1)
open(p, "w").write(s2)
PY
info "[keystore.tls] uses gateway-tls.jks"
if ! keytool -list -keystore "$TRUSTSTORE" -storepass wso2carbon -alias idjag-demo-dev-ca >/dev/null 2>&1; then
  keytool -importcert -noprompt -alias idjag-demo-dev-ca -file "$CA_PEM" -keystore "$TRUSTSTORE" -storepass wso2carbon >/dev/null 2>&1
  info "dev CA added to client-truststore.jks (APIM calls its own gateway)"
fi

# --- 4. Atlassian mock ---------------------------------------------------------------------
say "Atlassian mock (code/atlassian-mock): virtualenv and tests"
( cd "$REPO/code/atlassian-mock" && ./run.sh --test ) | tail -1

say "Done. Next: scripts/start.sh, then scripts/configure.sh"
info "Trust the dev CA for VS Code (README, step 5): setup/certs/dev-ca.pem"
