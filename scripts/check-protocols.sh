#!/usr/bin/env bash
# Reuse Go from check-linux.sh; check real protocols and optionally systemd.
set -euo pipefail
if [[ $(uname -s) != Linux || $(id -u) == 0 ]]; then
  echo 'Run inside Linux/WSL as your normal user (without sudo).' >&2
  exit 1
fi
go_root=${1:?Pass the check-linux.sh directory containing go/bin/go}
if [[ ! -x "$go_root/go/bin/go" ]]; then
  echo "Go not found: $go_root/go/bin/go" >&2
  exit 1
fi
if [[ ${2:-} != '' && ${2:-} != --systemd ]]; then
  echo 'Usage: check-protocols.sh CHECK_DIRECTORY [--systemd]' >&2
  exit 1
fi
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
check_dir=$(mktemp -d "$HOME/hy-panel-protocols.XXXXXX")
trap 'printf "\nCheck directory: %s\nLog: %s/check.log\n" "$check_dir" "$check_dir"' EXIT
(
  set -euo pipefail
  export PATH="$go_root/go/bin:$PATH"
  unset GOROOT GOOS GOARCH
  export CGO_ENABLED=1
  go version
  echo '=== Verify cached protocol tools (download only if missing) ==='
  tool_cache=${HYP_PROTOCOL_CACHE:-"$HOME/.cache/hy-panel/protocol-tools"}
  python3 "$source_dir/scripts/download-test-tools.py" "$tool_cache"
  mkdir "$check_dir/project" "$check_dir/tools"
  for tool_name in hysteria xray xray-minimum mihomo; do
    install -m 755 "$tool_cache/$tool_name" "$check_dir/tools/$tool_name"
  done
  (cd "$source_dir" && git -c safe.directory="$source_dir" ls-files --cached --others --exclude-standard -z |
    while IFS= read -r -d '' source_file; do
      if [[ -e "$source_file" || -L "$source_file" ]]; then printf '%s\0' "$source_file"; fi
    done |
    tar --null --verbatim-files-from --files-from=- -cf -) |
    tar -xf - -C "$check_dir/project"
  cd "$check_dir/project"
  export HYSTERIA_BIN="$check_dir/tools/hysteria"
  export XRAY_BIN="$check_dir/tools/xray"
  export XRAY_MINIMUM_BIN="$check_dir/tools/xray-minimum"
  export MIHOMO_BIN="$check_dir/tools/mihomo"
  echo '=== Real Hysteria, VLESS/Reality and Mihomo integration ==='
  go test -race -tags=e2e -run '^TestE2E' -count=1 -timeout=5m -v .
  echo 'PROTOCOL CHECK PASSED'
  if [[ ${2:-} == --systemd ]]; then
    echo '=== Build opt-in systemd test ==='
    CGO_ENABLED=0 go build -o "$check_dir/hy-panel-candidate" .
    go test -tags=systemd -c -o "$check_dir/systemd.test" .
    echo '=== Temporary systemd installation, migration, agent and rollback ==='
    sudo env HYP_SYSTEMD_SMOKE=1 \
      HYP_PANEL_BIN="$check_dir/hy-panel-candidate" \
      HYSTERIA_BIN="$HYSTERIA_BIN" XRAY_BIN="$XRAY_BIN" \
      "$check_dir/systemd.test" -test.run '^TestSystemdLifecycle$' -test.v -test.timeout=10m
    echo 'SYSTEMD CHECK PASSED'
  fi
) 2>&1 | tee "$check_dir/check.log"
