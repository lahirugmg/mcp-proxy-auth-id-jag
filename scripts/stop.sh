#!/usr/bin/env bash
#
# stop.sh — stop the Atlassian mock, API Manager and WSO2 IS.
#
# The gateway keeps each user's ID token in memory, so after a restart Copilot's
# next tool call is answered "Sign in again"; signing in once more fixes it.

set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

say "Stopping"
if [[ -f "$SETUP/logs/mock.pid" ]]; then
  kill -- "-$(cat "$SETUP/logs/mock.pid")" 2>/dev/null || kill "$(cat "$SETUP/logs/mock.pid")" 2>/dev/null || true
  rm -f "$SETUP/logs/mock.pid"
fi
pid=$(lsof -ti tcp:9500 -sTCP:LISTEN 2>/dev/null || true)
[[ -n "$pid" ]] && kill $pid 2>/dev/null || true
info "Atlassian mock stopped"

stop_wso2() {   # stop_wso2 <home> <script> <name>
  local pid_file="$1/wso2carbon.pid" pid
  [[ -n "$1" && -f "$pid_file" ]] || { info "$3 not running"; return; }
  pid=$(tr -cd '0-9' < "$pid_file")
  sh "$1/bin/$2" stop >/dev/null 2>&1 || true
  for _ in $(seq 1 60); do kill -0 "$pid" 2>/dev/null || break; sleep 2; done
  info "$3 stopped"
}
stop_wso2 "$APIM_HOME" api-manager.sh "API Manager"
stop_wso2 "$IS_HOME" wso2server.sh "WSO2 IS"
