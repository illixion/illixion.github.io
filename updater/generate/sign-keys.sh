#!/usr/bin/env bash
#
# sign-keys.sh — build and sign the authorized_keys manifest.
#
# Reads the human-edited key list (default ../../ssh.keys), assembles a manifest
# JSON with an auto-incremented serial, signs it as an SSHSIG, self-verifies
# against pinned_signers, then regenerates the page. Output lands in the website
# tree so a `git push` ships it.
#
# Signing uses an SSH agent by default, with one of the keys in pinned_signers
# (the single source of trust — no separate .pub file needed). The script finds
# whichever reachable agent holds that key (your ssh-agent, or gpg-agent for
# PGP/PIV-applet keys). For an offline backup key, sign with --key-file instead.
#
# Usage:
#   ./sign-keys.sh                          # sign as the first pinned signer
#   ./sign-keys.sh --signer you@backup      # sign as a specific pinned signer (comment or index)
#   ./sign-keys.sh --key-file ~/key_ed25519 # sign with an offline private key
#   ./sign-keys.sh --gpg-agent              # force gpg-agent's ssh socket
#   ./sign-keys.sh --disable you@yubikey --key-file ~/backup_ed25519   # revoke a signer
#
set -euo pipefail

TMPFILES=()
cleanup() { [[ ${#TMPFILES[@]} -gt 0 ]] && rm -f "${TMPFILES[@]}"; }
trap cleanup EXIT

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UPDATER_DIR="$(cd "$HERE/.." && pwd)"       # ssh/updater/
SSH_DIR="$(cd "$UPDATER_DIR/.." && pwd)"    # ssh/    (manifest + page + keys.list live here)

# Load deployment config (BASE_URL, TITLE, HANDLE, SOURCE_KEYS).
[[ -f "$UPDATER_DIR/config.env" ]] && source "$UPDATER_DIR/config.env"
: "${SKU_BASE_URL:=https://example.com/ssh}"
: "${SKU_TITLE:=}"; : "${SKU_HANDLE:=}"; : "${SKU_REPO_URL:=}"; : "${SKU_SOURCE_KEYS:=keys.list}"

# Resolve the source key list (relative paths are under ssh/).
case "$SKU_SOURCE_KEYS" in
  /*) SOURCE_KEYS="$SKU_SOURCE_KEYS" ;;
  *)  SOURCE_KEYS="$SSH_DIR/$SKU_SOURCE_KEYS" ;;
esac
MANIFEST="$SSH_DIR/manifest.json"
SIG="$MANIFEST.sig"
PINNED="$UPDATER_DIR/pinned_signers"

SIGNER=""                     # pinned signer to use: comment or 1-based index (default: first)
KEY_FILE="${SKU_KEY_FILE:-}"  # sign with this private key file instead of an agent
USE_GPG_AGENT=0               # force routing through gpg-agent's ssh socket
DISABLE_SIGNER=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --signer) SIGNER="$2"; shift 2 ;;
    --key-file) KEY_FILE="$2"; shift 2 ;;
    --gpg-agent) USE_GPG_AGENT=1; shift ;;
    --disable) DISABLE_SIGNER="$2"; shift 2 ;;
    --source) SOURCE_KEYS="$2"; shift 2 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

command -v python3 >/dev/null || { echo "python3 required" >&2; exit 1; }

# pick_signer <comment|index|""> — echo the chosen "algo blob comment" pinned line.
pick_signer() {
  local want="$1" i=0 algo blob comment _
  while read -r algo blob comment _; do
    [[ -z "${algo:-}" || "$algo" == \#* ]] && continue
    i=$((i + 1))
    if [[ ( -z "$want" && $i -eq 1 ) || "$want" == "$comment" || "$want" == "$i" ]]; then
      echo "$algo $blob $comment"; return 0
    fi
  done < "$PINNED"
  return 1
}

# agent_has_key <socket> <keyblob> — true if that agent currently holds the key.
agent_has_key() {
  [[ -n "${1:-}" ]] || return 1
  SSH_AUTH_SOCK="$1" ssh-add -L 2>/dev/null | grep -qF "$2"
}

# Next serial = (current published serial) + 1, or 1 if none.
prev_serial=0
if [[ -f "$MANIFEST" ]]; then
  prev_serial="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("serial",0))' "$MANIFEST")"
fi
serial=$(( prev_serial + 1 ))
issued_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo ">> building manifest serial=$serial from $SOURCE_KEYS"

# Extract non-comment, non-blank key lines from the source file.
mapfile -t KEYS < <(grep -vE '^[[:space:]]*(#|$)' "$SOURCE_KEYS")
if [[ ${#KEYS[@]} -eq 0 && -z "$DISABLE_SIGNER" ]]; then
  echo "no keys found in $SOURCE_KEYS" >&2; exit 1
fi

# Build canonical JSON with python3 (handles escaping; stable key order).
python3 - "$serial" "$issued_at" "$DISABLE_SIGNER" "${KEYS[@]}" >"$MANIFEST" <<'PY'
import json, sys
serial = int(sys.argv[1]); issued_at = sys.argv[2]; disable = sys.argv[3]
keys = [k.strip() for k in sys.argv[4:] if k.strip()]
m = {"schema": 1, "serial": serial, "issued_at": issued_at, "keys": keys}
if disable:
    m["disable_signer"] = disable
sys.stdout.write(json.dumps(m, indent=2, ensure_ascii=False) + "\n")
PY

rm -f "$SIG"   # ssh-keygen -Y sign writes <file>.sig and prompts if it exists

if [[ -n "$KEY_FILE" ]]; then
  echo ">> signing with key file $KEY_FILE"
  [[ -f "$KEY_FILE" ]] || { echo "key file not found: $KEY_FILE" >&2; exit 1; }
  ssh-keygen -Y sign -n file -f "$KEY_FILE" "$MANIFEST"
else
  SIGNER_LINE="$(pick_signer "$SIGNER")" || { echo "no pinned signer matches '${SIGNER:-<first>}'" >&2; exit 1; }
  SIGNER_BLOB="$(awk '{print $2}' <<<"$SIGNER_LINE")"
  SIGNER_NAME="$(awk '{print $3}' <<<"$SIGNER_LINE")"

  # Find an agent holding this key: explicit --gpg-agent, else the current
  # SSH_AUTH_SOCK, else gpg-agent's ssh socket (PGP/PIV-applet keys).
  if [[ "$USE_GPG_AGENT" -eq 1 ]]; then
    export SSH_AUTH_SOCK="$(gpgconf --list-dirs agent-ssh-socket)"; gpgconf --launch gpg-agent || true
  elif ! agent_has_key "${SSH_AUTH_SOCK:-}" "$SIGNER_BLOB"; then
    gpgsock="$(gpgconf --list-dirs agent-ssh-socket 2>/dev/null || true)"
    if [[ -n "$gpgsock" ]] && { gpgconf --launch gpg-agent 2>/dev/null; agent_has_key "$gpgsock" "$SIGNER_BLOB"; }; then
      export SSH_AUTH_SOCK="$gpgsock"
    fi
  fi
  agent_has_key "${SSH_AUTH_SOCK:-}" "$SIGNER_BLOB" || {
    echo "signer '$SIGNER_NAME' is not loaded in any reachable ssh-agent;" >&2
    echo "plug in/unlock the token, or use --key-file for an offline key." >&2; exit 1; }

  PUBTMP="$(mktemp)"; TMPFILES+=("$PUBTMP")
  printf '%s\n' "$SIGNER_LINE" > "$PUBTMP"
  echo ">> signing as $SIGNER_NAME (touch your security key if it blinks)"
  ssh-keygen -Y sign -n file -f "$PUBTMP" "$MANIFEST"
fi
# ssh-keygen wrote "$MANIFEST.sig", which is exactly "$SIG".

# Self-verify against the pinned signers before publishing, using ssh-keygen's
# own verifier built from an allowed_signers derived from pinned_signers.
echo ">> self-verifying with ssh-keygen -Y verify"
ALLOWED="$(mktemp)"; TMPFILES+=("$ALLOWED")
while read -r algo b64 comment _; do
  [[ -z "${algo:-}" || "$algo" == \#* ]] && continue
  echo "$comment $algo $b64" >>"$ALLOWED"
done <"$PINNED"

# Try each pinned identity until one verifies (we don't know which signed it).
ok=0
while read -r identity _; do
  if ssh-keygen -Y verify -f "$ALLOWED" -I "$identity" -n file -s "$SIG" <"$MANIFEST" 2>/dev/null; then
    echo "   verified as: $identity"; ok=1; break
  fi
done < <(awk '{print $1}' "$ALLOWED")
[[ $ok -eq 1 ]] || { echo "SELF-VERIFY FAILED — not publishing" >&2; exit 1; }

# Publish discovery.json — the small PUBLIC descriptor clients fetch to learn
# where the manifest lives and the recommended cadence. Location/convenience
# only; never trust material (the signing keys are compiled into the binary).
DISCOVERY="$SSH_DIR/discovery.json"
echo ">> writing $DISCOVERY"
python3 - "$SKU_BASE_URL" "${SKU_INTERVAL:-15m}" "${SKU_SPLAY:-15m}" "$SKU_TITLE" "$SKU_HANDLE" "$SKU_REPO_URL" >"$DISCOVERY" <<'PY'
import json, sys
base = sys.argv[1].rstrip("/")
d = {
    "schema": 1,
    "base_url": base,
    "manifest_url": base + "/manifest.json",
    "interval": sys.argv[2],
    "splay": sys.argv[3],
    "title": sys.argv[4],
    "handle": sys.argv[5],
    "repo_url": sys.argv[6],
}
sys.stdout.write(json.dumps(d, indent=2, ensure_ascii=False) + "\n")
PY

# Regenerate the static page (independent of serial/keys — those load
# client-side — but keep it in sync with pins/URL/identity).
if command -v go >/dev/null; then
  echo ">> regenerating page -> $SSH_DIR/index.html"
  ( cd "$UPDATER_DIR" && go run . gen-page \
      -base-url "$SKU_BASE_URL" -title "$SKU_TITLE" -handle "$SKU_HANDLE" \
      -repo "$SKU_REPO_URL" -out "$SSH_DIR/index.html" )
fi

echo ""
echo "Wrote:"
echo "  $MANIFEST"
echo "  $SIG"
echo "  $DISCOVERY"
echo "  $SSH_DIR/index.html"
echo "Review, then: git add -A && git commit -m 'keys: serial $serial' && git push"
