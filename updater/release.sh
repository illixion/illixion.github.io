#!/usr/bin/env bash
#
# release.sh — cross-compile the updater for every target.
#
# Produces static, dependency-free binaries in dist/. These are distributed
# OUT-OF-BAND (USB, an existing trusted SSH session) and preloaded — never
# downloaded from the website, which is untrusted by design. Each binary has the
# signer trust anchor (pinned_signers) baked in via go:embed.
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

PUBLISH=0
VERSION=""
for a in "$@"; do
  case "$a" in
    --publish) PUBLISH=1 ;;        # also stage binaries into ../bin for the website
    *) VERSION="$a" ;;
  esac
done
[ -n "$VERSION" ] || VERSION="$(git -C .. describe --tags --always 2>/dev/null || echo dev)"
OUT="dist"
rm -rf "$OUT"; mkdir -p "$OUT"

# Bake deployment config into the binaries so `install` on a client targets the
# right manifest URL with no flags. Edit config.env, not this file.
[[ -f config.env ]] && source config.env
: "${SKU_BASE_URL:=https://example.com/ssh}"; : "${SKU_TITLE:=}"; : "${SKU_HANDLE:=}"; : "${SKU_REPO_URL:=}"
echo ">> base URL: $SKU_BASE_URL"

# Values are single-quoted so titles/handles with spaces survive (the go tool
# splits -ldflags with quote awareness).
LDFLAGS="-s -w -X main.version=$VERSION \
  -X 'main.defaultBaseURL=$SKU_BASE_URL' \
  -X 'main.defaultTitle=$SKU_TITLE' \
  -X 'main.defaultHandle=$SKU_HANDLE' \
  -X 'main.defaultRepoURL=$SKU_REPO_URL'"

# GOOS GOARCH [extra env] suffix
targets=(
  "darwin  arm64                       macos-arm64"
  "darwin  amd64                       macos-amd64"
  "linux   amd64                       linux-amd64"
  "linux   arm64                       linux-arm64"
  "windows amd64                       windows-amd64.exe"
  "windows arm64                       windows-arm64.exe"
  "linux   mipsle GOMIPS=softfloat     openwrt-ramips"   # ramips/mt76x8 etc.
)

for t in "${targets[@]}"; do
  read -r goos goarch a b <<<"$t"
  # The optional GOMIPS env lands in $a; the suffix is the last token.
  if [[ "$a" == GOMIPS=* ]]; then export "${a?}"; suffix="$b"; else suffix="$a"; unset GOMIPS 2>/dev/null||true; fi
  bin="$OUT/ssh-keys-updater-$suffix"
  echo ">> $goos/$goarch ${GOMIPS:+($a) }-> $bin"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags "$LDFLAGS" -o "$bin" .
done
unset GOMIPS 2>/dev/null || true

echo ""
echo ">> checksums"
( cd "$OUT" && shasum -a 256 * | tee SHA256SUMS )

if [ "$PUBLISH" -eq 1 ]; then
  BIN="../bin"
  echo ""
  echo ">> publishing to $BIN (served at $SKU_BASE_URL/bin/)"
  mkdir -p "$BIN"
  cp "$OUT"/ssh-keys-updater-* "$OUT/SHA256SUMS" "$BIN/"
  echo "   staged $(ls "$BIN" | wc -l | tr -d ' ') files — review, then git add bin && commit && push"
  echo "   NOTE: record dist/SHA256SUMS out-of-band (mobile note) — that's what users compare against."
fi

echo ""
echo "Binaries in $OUT/. Preload over a trusted channel OR publish + verify by SHA-256."
echo "Then on each host:  ./ssh-keys-updater-<target> install   # schedules periodic checks + runs once"
echo "See INSTALL.md for the per-platform download+verify+install flow."
