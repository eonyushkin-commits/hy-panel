#!/usr/bin/env bash
# bash <(curl -fsSL https://raw.githubusercontent.com/eonyushkin-commits/hy-panel/main/install.sh) [-name AMS] [-host IP]
# Downloads the release binary for this CPU, checks SHA256SUMS and runs `hy-panel install`.
# HY_PANEL_VERSION=v0.1.0 pins a version (default: latest release).
set -euo pipefail

REPO=eonyushkin-commits/hy-panel
BASE=${HY_PANEL_BASE:-https://github.com/$REPO/releases}
VERSION=${HY_PANEL_VERSION:-latest}

[ "$(id -u)" = 0 ] || { echo "запусти от root" >&2; exit 1; }
case "$(uname -m)" in
  x86_64 | amd64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) echo "неподдерживаемая архитектура: $(uname -m)" >&2; exit 1 ;;
esac
command -v curl >/dev/null || { echo "нужен curl" >&2; exit 1; }

if [ "$VERSION" = latest ]; then URL=$BASE/latest/download; else URL=$BASE/download/$VERSION; fi
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "→ $URL/hy-panel-linux-$ARCH"
curl -fsSL -o "$TMP/hy-panel-linux-$ARCH" "$URL/hy-panel-linux-$ARCH"
curl -fsSL -o "$TMP/SHA256SUMS" "$URL/SHA256SUMS"
(cd "$TMP" && grep " hy-panel-linux-$ARCH\$" SHA256SUMS | sha256sum -c --quiet) || { echo "контрольная сумма не совпала" >&2; exit 1; }
chmod +x "$TMP/hy-panel-linux-$ARCH"

"$TMP/hy-panel-linux-$ARCH" install "$@"
