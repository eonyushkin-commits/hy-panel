#!/usr/bin/env bash
# Native Linux verification in a fresh copy, including uncommitted source files.
# No VPN services are installed, stopped or restarted by this script.
set -euo pipefail

if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
  echo 'This check requires Linux x86_64.' >&2
  exit 1
fi
if [[ $(id -u) == 0 ]]; then
  echo 'Run without sudo: permission tests must run as an ordinary user.' >&2
  exit 1
fi
for check_tool in git curl sha256sum tar gcc; do
  command -v "$check_tool" >/dev/null || {
    echo "Missing tool: $check_tool (install build-essential, git, curl, ca-certificates)." >&2
    exit 1
  }
done

source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
check_dir=$(mktemp -d "$HOME/hy-panel-check.XXXXXX")
go_archive=${HYP_GO_ARCHIVE:-"$HOME/.cache/hy-panel-check/go1.27.3.linux-amd64.tar.gz"}
go_checksum=65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40
mkdir -p -- "$(dirname -- "$go_archive")"
trap 'printf "\nCheck directory: %s\nLog: %s/check.log\n" "$check_dir" "$check_dir"' EXIT

check_go_archive() {
  [[ -f "$go_archive" ]] &&
    printf '%s  %s\n' "$go_checksum" "$go_archive" | sha256sum --check --status
}

(
  set -euo pipefail
  echo '=== Toolchain: official Go archive with SHA-256 verification ==='
  if ! check_go_archive; then
    printf 'Download cache (partial downloads are kept): %s\n' "$go_archive"
    # A separate curl process re-evaluates the local offset after every failure.
    # Do not use --retry here: a retry must never truncate the partial archive.
    for check_attempt in 1 2 3; do
      if curl --fail --location --show-error --connect-timeout 20 --max-time 0 \
        --speed-time 120 --speed-limit 1024 --continue-at - --output "$go_archive" \
        https://go.dev/dl/go1.27.3.linux-amd64.tar.gz; then
        break
      fi
      if [[ "$check_attempt" == 3 ]]; then
        echo 'Download interrupted. Run this script again to resume.' >&2
        exit 1
      fi
      echo 'Connection stalled; resuming the saved partial archive...'
      sleep 2
    done
    if ! check_go_archive; then
      printf 'SHA-256 mismatch: %s. The archive was not extracted.\n' "$go_archive" >&2
      exit 1
    fi
  else
    echo 'Using cached Go archive (SHA-256 verified).'
  fi
  tar -xzf "$go_archive" -C "$check_dir"
  export PATH="$check_dir/go/bin:$PATH"
  unset GOROOT GOOS GOARCH
  export CGO_ENABLED=1
  go version
  printf 'GCC: '
  gcc -dumpfullversion

  echo '=== Copy current sources onto the Linux filesystem ==='
  mkdir "$check_dir/project" "$check_dir/dist"
  (
    cd "$source_dir"
    git -c safe.directory="$source_dir" ls-files --cached --others --exclude-standard -z |
      while IFS= read -r -d '' source_file; do
        if [[ -e "$source_file" || -L "$source_file" ]]; then printf '%s\0' "$source_file"; fi
      done |
      tar --null --verbatim-files-from --files-from=- -cf -
  ) | tar -xf - -C "$check_dir/project"
  cd "$check_dir/project"
  printf 'Source copy: %s\n' "$PWD"

  echo '=== go vet ==='
  go vet ./...
  echo '=== All Linux tests with race detector ==='
  go test -race -count=1 -timeout=5m ./...
  echo '=== Compile real-protocol integration tests ==='
  go test -tags=e2e -c -o "$check_dir/dist/integration.test" .
  echo '=== Linux release builds ==='
  for check_arch in amd64 arm64; do
    CGO_ENABLED=0 GOOS=linux GOARCH="$check_arch" go build -trimpath \
      -ldflags='-s -w' -o "$check_dir/dist/hy-panel-linux-$check_arch" .
  done
  (cd "$check_dir/dist" && sha256sum hy-panel-linux-* > SHA256SUMS)
  echo 'LINUX CHECK PASSED'
) 2>&1 | tee "$check_dir/check.log"
