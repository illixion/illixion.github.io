#!/usr/bin/env bash
#
# update-host.sh — roll this checkout's ssh-keys-updater build out to hosts.
#
#   ./update-host.sh [--dry-run] [--allow-dirty] <host> [<host>...]
#
# <host> is anything `ssh` accepts (an ~/.ssh/config alias, user@host, ...).
# For each host it:
#   1. detects the OS/arch (macOS, Linux incl. OpenWRT, Windows),
#   2. finds every installed copy, user- or system-scope: the sidecar's
#      exe_path, the scheduler unit (launchd/systemd/cron/schtasks) and the
#      canonical system-install paths,
#   3. uploads the matching binary from a fresh local build (release.sh) and
#      checks its SHA-256 on arrival,
#   4. runs the NEW binary's `self-update` against each installed path (as
#      root via sudo when that path isn't writable), which swaps it in and
#      does one verification run.
#
# The binary always comes from the local reproducible build, never from the
# site (which is untrusted by design). The site's bin/SHA256SUMS is fetched
# only as a cross-check: a mismatch means CI hasn't deployed this version yet,
# or the builds diverged.
#
# One SSH connection per host is reused for every step (ControlMaster), so a
# Touch ID / security-key prompt happens once per host.
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

DRY=0
ALLOW_DIRTY=0
hosts=()
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    --allow-dirty) ALLOW_DIRTY=1 ;;
    -h|--help) sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown option: $a" >&2; exit 2 ;;
    *) hosts+=("$a") ;;
  esac
done
[ ${#hosts[@]} -gt 0 ] || { echo "usage: $0 [--dry-run] [--allow-dirty] <host> [<host>...]" >&2; exit 2; }

# A dirty tree would ship code that doesn't match the baked version string.
if [ "$ALLOW_DIRTY" -eq 0 ] && [ -n "$(git -C .. status --porcelain -- updater)" ]; then
  echo "updater/ has uncommitted changes; commit first or pass --allow-dirty" >&2
  exit 1
fi

VERSION="$(git -C .. describe --tags --always 2>/dev/null || echo dev)"
echo ">> building $VERSION"
./release.sh "$VERSION" >/dev/null
BASE_URL="$( . ./config.env >/dev/null 2>&1; printf '%s' "${SKU_BASE_URL:-}" )"
SITE_SUMS=""
if [ -n "$BASE_URL" ]; then
  SITE_SUMS="$(curl -fsS --max-time 10 "$BASE_URL/bin/SHA256SUMS" 2>/dev/null || true)"
fi

# Short path on purpose: a ControlPath must fit in sun_path (104 bytes on
# macOS), which $TMPDIR under /var/folders would overflow.
CTL="$(mktemp -d /tmp/sku-ssh.XXXXXX)"
cleanup() {
  for s in "$CTL"/*; do
    [ -S "$s" ] && ssh -o ControlPath="$s" -O exit _ >/dev/null 2>&1 || true
  done
  rm -rf "$CTL"
}
trap cleanup EXIT
SSHO=(-o ControlMaster=auto -o "ControlPath=$CTL/%C" -o ControlPersist=300 -o ConnectTimeout=10)

host=""
rsh() { ssh "${SSHO[@]}" "$host" "$@"; }

# Run a PowerShell script on a Windows host (not named ps: that shadows ps(1)). -EncodedCommand (UTF-16LE base64)
# sidesteps quoting whether the remote default shell is cmd or PowerShell.
pwsh_run() {
  local b64
  b64="$(printf "\$ProgressPreference='SilentlyContinue'\n%s" "$1" | iconv -f UTF-8 -t UTF-16LE | base64 | tr -d '\n')"
  rsh "powershell -NoProfile -NonInteractive -EncodedCommand $b64" </dev/null | tr -d '\r'
}

sha256_local() { shasum -a 256 "$1" | awk '{print $1}'; }

# POSIX sh (busybox-safe) probe. Prints one line per installed copy:
#   bin<TAB><path><TAB><needs-sudo 0|1><TAB><version>
# plus "insecure" when a unit passes -insecure-tls, "overlayroot" when the
# root filesystem is an overlay whose writes don't survive a reboot, and
# "root" when the SSH user is root.
UNIX_PROBE='
cands=""
add() { [ -n "$1" ] && [ -f "$1" ] && cands="$cands
$1"; }
for sc in "$HOME/.ssh/.ssh-keys-updater.json" /root/.ssh/.ssh-keys-updater.json \
          /var/root/.ssh/.ssh-keys-updater.json /etc/dropbear/.ssh-keys-updater.json; do
  [ -r "$sc" ] && add "$(sed -n "s/.*\"exe_path\": *\"\([^\"]*\)\".*/\1/p" "$sc")"
done
units=""
for u in /etc/systemd/system/ssh-keys-updater.service \
         "$HOME/.config/systemd/user/ssh-keys-updater.service"; do
  [ -r "$u" ] || continue
  units="$units $(cat "$u")"
  for p in $(sed -n "s/^ExecStart=[-@+!]*\([^ ]*\).*/\1/p" "$u"); do add "$p"; done
done
for pl in /Library/LaunchDaemons/com.illixion.ssh-keys-updater.plist \
          "$HOME/Library/LaunchAgents/com.illixion.ssh-keys-updater.plist"; do
  [ -r "$pl" ] || continue
  units="$units $(cat "$pl")"
  add "$(sed -n "s:.*<string>\(/[^<]*/ssh-keys-updater[^/<]*\)</string>.*:\1:p" "$pl" | head -n 1)"
done
cron="$(crontab -l 2>/dev/null; cat /etc/crontabs/root 2>/dev/null)"
cron="$(printf "%s\n" "$cron" | grep "# ssh-keys-updater" || true)"
units="$units $cron"
for p in $(printf "%s\n" "$cron" | awk "{print \$6}" | tr -d "'\''"); do add "$p"; done
add /usr/local/bin/ssh-keys-updater
add /usr/bin/ssh-keys-updater
add "$(command -v ssh-keys-updater 2>/dev/null)"
case "$units" in *-insecure-tls*) echo insecure ;; esac
[ -d /media/root-ro ] && echo overlayroot
[ "$(id -u)" = 0 ] && echo root
printf "%s\n" "$cands" | while read -r p; do
  [ -n "$p" ] || continue
  readlink -f "$p" 2>/dev/null || printf "%s\n" "$p"
done | sort -u | while read -r p; do
  s=1
  if [ "$(id -u)" = 0 ] || { [ -w "$p" ] && [ -w "$(dirname "$p")" ]; }; then s=0; fi
  printf "bin\t%s\t%s\t%s\n" "$p" "$s" "$("$p" version 2>/dev/null | head -n 1)"
done
'

# PowerShell probe; same output format as UNIX_PROBE. Admin sessions over
# Windows OpenSSH are already elevated, so needs-sudo is always 0.
WIN_PROBE='
$c = @()
foreach ($sc in @("$env:USERPROFILE\.ssh\.ssh-keys-updater.json", "$env:ProgramData\ssh\.ssh-keys-updater.json")) {
  if (Test-Path $sc) { try { $j = Get-Content -Raw $sc | ConvertFrom-Json; if ($j.exe_path) { $c += $j.exe_path } } catch {} }
}
$c += "$env:ProgramFiles\ssh-keys-updater\ssh-keys-updater.exe"
$t = schtasks /Query /TN ssh-keys-updater /XML 2>$null
if ($t) {
  $x = [xml]($t -join "`n")
  foreach ($e in $x.Task.Actions.Exec) {
    if ($e.Command) { $c += $e.Command.Trim([char]34) }
    if ("$($e.Arguments)" -match "-insecure-tls") { "insecure" }
  }
}
$c | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | ForEach-Object { (Resolve-Path -LiteralPath $_).Path } | Sort-Object -Unique | ForEach-Object {
  $v = (& $_ version 2>$null | Select-Object -First 1)
  "bin`t$_`t0`t$v"
}
'

binary_for() { # <os> <uname -m | PROCESSOR_ARCHITECTURE> <is-openwrt>
  case "$1:$2" in
    darwin:arm64) echo macos-arm64 ;;
    darwin:x86_64) echo macos-amd64 ;;
    linux:x86_64|linux:amd64) echo linux-amd64 ;;
    linux:aarch64|linux:arm64) echo linux-arm64 ;;
    linux:mips) [ "$3" = 1 ] && echo openwrt-ramips ;;
    windows:AMD64) echo windows-amd64.exe ;;
    windows:ARM64) echo windows-arm64.exe ;;
  esac
}

update_host() {
  host="$1"
  echo ""
  echo "== $host"

  local os arch openwrt=0 probe
  local un rc=0
  un="$(rsh 'uname -sm; [ -f /etc/openwrt_release ] && echo openwrt' </dev/null 2>/dev/null)" || rc=$?
  # 255 is ssh's own failure; anything else means we connected but there's no
  # uname, i.e. a Windows shell.
  [ "$rc" -ne 255 ] || { echo "   unreachable" >&2; return 1; }
  case "$un" in
    Darwin\ *) os=darwin ;;
    Linux\ *) os=linux ;;
    *) os=windows ;;
  esac
  if [ "$os" = windows ]; then
    arch="$(pwsh_run '$env:PROCESSOR_ARCHITECTURE')"
    [ -n "$arch" ] || { echo "   cannot detect the OS (no uname, no PowerShell)" >&2; return 1; }
    probe="$(pwsh_run "$WIN_PROBE")"
  else
    arch="$(printf '%s\n' "$un" | head -n 1 | awk '{print $2}')"
    case "$un" in *openwrt*) openwrt=1 ;; esac
    probe="$(rsh 'sh -s' <<<"$UNIX_PROBE")"
  fi

  local name
  name="$(binary_for "$os" "$arch" "$openwrt")"
  [ -n "$name" ] || { echo "   no build target for $os/$arch" >&2; return 1; }
  local file="dist/ssh-keys-updater-$name" sum
  sum="$(sha256_local "$file")"
  echo "   $os/$arch -> $name ($sum)"
  if [ -n "$SITE_SUMS" ]; then
    local site
    site="$(printf '%s\n' "$SITE_SUMS" | awk -v n="ssh-keys-updater-$name" '$2 == n {print $1}')"
    if [ "$site" = "$sum" ]; then
      echo "   matches $BASE_URL/bin/SHA256SUMS"
    else
      echo "   WARNING: differs from $BASE_URL/bin/SHA256SUMS (${site:-absent}); CI not deployed yet, or builds diverged"
    fi
  fi

  local insecure=""
  grep -qx insecure <<<"$probe" && insecure="-insecure-tls"
  if grep -qx overlayroot <<<"$probe"; then
    echo "   WARNING: overlayroot host; a binary on the overlay reverts at reboot unless its path is on a persistent mount"
  fi

  local as=user
  grep -qx root <<<"$probe" && as=root
  local -a paths=() sudos=()
  local tag p s v
  while IFS=$'\t' read -r tag p s v; do
    [ "$tag" = bin ] || continue
    paths+=("$p"); sudos+=("$s")
    echo "   installed: $p (runs $([ "$s" = 1 ] && echo "via sudo" || echo "as $as")) — ${v:-version unknown}"
  done <<<"$probe"
  if [ ${#paths[@]} -eq 0 ]; then
    echo "   no installed ssh-keys-updater found; install it first (system-install)" >&2
    return 1
  fi
  [ "$DRY" -eq 1 ] && { echo "   dry run: nothing changed"; return 0; }

  local i out
  if [ "$os" = windows ]; then
    local remote='.ssh-keys-updater.new.exe'
    scp -q "${SSHO[@]}" "$file" "$host:$remote"
    local got
    got="$(pwsh_run "(Get-FileHash -Algorithm SHA256 \"\$env:USERPROFILE\\$remote\").Hash.ToLower()")"
    [ "$got" = "$sum" ] || { echo "   upload corrupted ($got)" >&2; return 1; }
    local rc=0
    for i in "${!paths[@]}"; do
      echo "   self-update ${paths[$i]}"
      out="$(pwsh_run "\$n = \"\$env:USERPROFILE\\$remote\"
& \$n self-update \$n -exe '${paths[$i]}' $insecure 2>&1
\"EXIT=\$LASTEXITCODE\"")"
      printf '%s\n' "$out" | grep -v '^EXIT=' | sed 's/^/     /'
      # Windows OpenSSH doesn't carry remote exit codes; read the marker instead.
      grep -qx 'EXIT=0' <<<"$out" || rc=1
    done
    pwsh_run "Remove-Item -Force \"\$env:USERPROFILE\\$remote\"" >/dev/null || true
    return "$rc"
  fi

  local remote='.ssh-keys-updater.new'
  rsh "cat > $remote && chmod 755 $remote" <"$file"
  local got
  got="$(rsh "{ sha256sum $remote 2>/dev/null || shasum -a 256 $remote; } | awk '{print \$1}'" </dev/null)"
  [ "$got" = "$sum" ] || { echo "   upload corrupted ($got)" >&2; rsh "rm -f $remote" </dev/null || true; return 1; }

  local rc=0 sudo tty
  for i in "${!paths[@]}"; do
    sudo=""; tty=(); local in=/dev/null
    if [ "${sudos[$i]}" = 1 ]; then
      sudo="sudo -H"
      # Passwordless sudo needs no TTY; otherwise allocate one for the prompt.
      rsh 'sudo -n true' </dev/null >/dev/null 2>&1 || { tty=(-t); in=/dev/tty; }
    fi
    echo "   self-update ${paths[$i]}${sudo:+ (sudo)}"
    # "$HOME/..." expands remotely to the SSH user's home, even under sudo -H.
    rsh "${tty[@]}" "$sudo \"\$HOME/$remote\" self-update \"\$HOME/$remote\" -exe '${paths[$i]}' $insecure" <"$in" 2>&1 | sed 's/^/     /' \
      || rc=1
  done
  rsh "rm -f $remote" </dev/null || true
  return "$rc"
}

failed=()
for h in "${hosts[@]}"; do
  update_host "$h" || failed+=("$h")
done
echo ""
if [ ${#failed[@]} -gt 0 ]; then
  echo "FAILED: ${failed[*]}" >&2
  exit 1
fi
echo "done: ${hosts[*]}"
