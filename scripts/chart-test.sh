#!/usr/bin/env bash
# Render the Helm chart with different values and check the output:
# config.json must be valid JSON with the expected content, probes must not
# need a shell, and Slack settings must reach the config and environment.
set -euo pipefail

CHART="$(dirname "$0")/../charts/pressured"
failed=0

render() { helm template t "$CHART" "$@"; }

# check <name> <python expression over `c` (config), `out` (rendered text) and
# `docs` (rendered documents)> <helm args...>
check() {
  local name=$1 expr=$2
  shift 2
  local out
  if ! out=$(render "$@" 2>&1); then
    echo "FAIL $name: helm template failed: $out"
    failed=1
    return
  fi
  if printf '%s' "$out" | python3 -c '
import json, sys
out = sys.stdin.read()
docs = out.split("\n---")
cm = next(d for d in docs if "config.json: |" in d)
body = cm.split("config.json: |", 1)[1].splitlines()
c = json.loads("\n".join(l[4:] for l in body))
sys.exit(0 if eval(sys.argv[1]) else 1)' "$expr"; then
    echo "ok   $name"
  else
    echo "FAIL $name"
    failed=1
  fi
}

# expect_fail <name> <message substring> <helm args...>
expect_fail() {
  local name=$1 message=$2
  shift 2
  local out
  if out=$(render "$@" 2>&1); then
    echo "FAIL $name: rendered without error"
    failed=1
  elif [[ "$out" == *"$message"* ]]; then
    echo "ok   $name"
  else
    echo "FAIL $name: unexpected error: $out"
    failed=1
  fi
}

check "defaults: valid JSON, kubelet mode" \
  'c["source"]["mode"] == "kubelet" and "plugins" not in c'
check "cgroup mode uses cgroup poll interval" \
  'c["source"]["mode"] == "cgroup" and c["source"]["poll_interval_ms"] == 1000' \
  --set mode=sidecar
check "lua timeout without scripts" \
  'c["plugins"]["lua"] == {"timeout_ms": 3000}' \
  --set lua.enabled=true --set lua.timeoutMs=3000
check "lua inline script" \
  'c["plugins"]["lua"]["inline_script"].startswith("function")' \
  --set lua.enabled=true --set-string 'lua.inlineScript=function on_event() end'
check "lua scripts dir + slack settings" \
  'c["plugins"]["lua"]["scripts_dir"] == "/scripts" and c["plugins"]["lua"]["slack"] == {"channels": "#alerts", "username": "Bot", "remind_seconds": 0}' \
  --set lua.enabled=true --set lua.existingConfigMap=x --set lua.slack.channels='#alerts' \
  --set lua.slack.username=Bot --set lua.slack.remindSeconds=0
check "slack token from secret, never in config" \
  '"secret" not in json.dumps(c) and "name: SLACK_BOT_TOKEN" in out and "name: slack-creds" in out and "key: slack-bot-token" in out' \
  --set lua.enabled=true --set lua.slack.existingSecret=slack-creds
check "s3 storage disables the local storage plugin" \
  'c["storage"]["s3"]["bucket"] == "b" and c["plugins"]["local-storage"] == {"enabled": False}' \
  --set storage.enabled=true --set storage.backend=s3 --set storage.s3.bucket=b
check "local storage" \
  'c["storage"] == {"backend": "local", "local": {"path": "/data/dumps"}} and "plugins" not in c' \
  --set storage.enabled=true
check "kubelet filters" \
  'c["source"]["kubelet"] == {"namespace_filter": "a,b", "label_selector": "app=x"}' \
  --set config.source.kubelet.namespace_filter='a\,b' --set config.source.kubelet.label_selector=app=x
check "probes run pressured, not a shell" \
  '"/bin/sh" not in out and "--health-check=120" in out and "--health-check=300" in out and "startupProbe:" in out' \
  --set image.tag=t
check "probes can be disabled" \
  '"Probe:" not in out' \
  --set image.tag=t --set healthCheck.enabled=false
check "single replica strategy is Recreate" \
  '"type: Recreate" in out' \
  --set image.tag=t
check "chart-managed scripts are mounted" \
  '"slack_notify.lua: |" in out and "mountPath: /scripts" in out' \
  --set lua.enabled=true --set-string 'lua.scripts.slack_notify\.lua=function on_event() end'
check "slack token env rendered once" \
  'out.count("name: SLACK_BOT_TOKEN") == 1' \
  --set image.tag=t --set lua.enabled=true --set lua.slack.existingSecret=s
expect_fail "slack token also in extraEnvVars is rejected" "remove it from extraEnvVars" \
  --set image.tag=t --set lua.enabled=true --set lua.slack.existingSecret=s \
  --set 'extraEnvVars[0].name=SLACK_BOT_TOKEN' --set 'extraEnvVars[0].value=x'
check "probe ages follow long poll intervals" \
  '"--health-check=1860" in out and "--health-check=1230" in out' \
  --set image.tag=t --set config.source.kubelet.poll_interval_ms=600000

# Changing a managed script must change the pod template (restart)
checksum() {
  render --set image.tag=t --set lua.enabled=true --set-string "lua.scripts.a\.lua=$1" |
    grep 'checksum/lua-scripts'
}
if [ "$(checksum 'return 1')" != "$(checksum 'return 2')" ]; then
  echo "ok   script change changes the pod template"
else
  echo "FAIL script change changes the pod template"
  failed=1
fi

exit $failed
