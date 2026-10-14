#!/usr/bin/env bash
#
# start.sh — start WSO2 IS (9444), API Manager (9443, gateway 8243) and the
# Atlassian mock (9500), and wait until each answers. All three keep running
# after this script exits; scripts/stop.sh stops them.
#
# Logs: setup/wso2is-7.3.0/repository/logs/wso2carbon.log,
#       setup/wso2am-4.6.0/repository/logs/wso2carbon.log, setup/logs/mock.log

set -euo pipefail
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
[[ -n "$IS_HOME" && -n "$APIM_HOME" ]] || die "run scripts/install.sh first"

say "Starting"
if is_up; then info "WSO2 IS already running"
else sh "$IS_HOME/bin/wso2server.sh" start >/dev/null 2>&1; info "WSO2 IS starting"; fi
if apim_up; then info "API Manager already running"
else sh "$APIM_HOME/bin/api-manager.sh" start >/dev/null 2>&1; info "API Manager starting"; fi
if mock_up; then info "Atlassian mock already running"
else
  mkdir -p "$SETUP/logs"
  # A session of its own, so the mock outlives the terminal that started it.
  ( cd "$REPO/code/atlassian-mock" && exec nohup python3 -c \
      'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' ./run.sh \
      > "$SETUP/logs/mock.log" 2>&1 < /dev/null ) &
  echo $! > "$SETUP/logs/mock.pid"
  info "Atlassian mock starting"
fi

say "Waiting"
wait_for mock_up 120 "Atlassian mock";  info "Atlassian mock  $MOCK"
wait_for is_up 300 "WSO2 IS";           info "WSO2 IS         $IS_BASE/console"
wait_for apim_up 400 "API Manager";     info "API Manager     $APIM/publisher"
wait_for gateway_up 120 "APIM gateway"; info "APIM gateway    $GATEWAY"
