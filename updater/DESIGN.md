# ssh-keys-updater

End-to-end-signed distribution of an SSH `authorized_keys` file. The website
(Cloudflare, GitHub, DNS, TLS) is treated as a **fully untrusted pipe**: even if
it returns attacker-chosen bytes with `200 OK`, no key of the attacker's
choosing can land in `authorized_keys`. Trust lives only in signing keys that
are preloaded onto each client out-of-band.

## Threat model

Defended:

- **Malicious `200 OK`** — compromised CDN/host/repo serving attacker content →
  rejected (no valid signature from a pinned key).
- **Replay / rollback** — serving an older but once-valid manifest that still
  lists a since-removed key → rejected (monotonic `serial`).
- **Signing-key compromise** — a stolen signing key → revoke it remotely with
  the *other* pinned key; a stolen key cannot un-revoke itself (revocation is
  persisted and serial-protected).

Out of scope: local root compromise of a client (can edit the binary, its state,
or `authorized_keys` directly). The pinned key is compiled into the binary, so
swapping the binary is a local-root action, not a network one.

By design there is **no expiry / freshness window** — all keys are
hardware-backed and the owner is not concerned with the freeze case. The only
anti-replay control is the serial counter, which never fails closed and never
locks you out.

## Components

```
Mac (trusted)                    ssh.illixion.com (UNTRUSTED)       each client
─────────────                    ────────────────────────        ───────────────
generate/sign-keys.sh   ─push─►  /discovery.json     ─GET─►  ssh-keys-updater <domain>
  reads keys.list                /manifest.json               (pinned keys compiled in)
  builds manifest                /manifest.json.sig           discover→verify→serial→
  signs (YubiKey/backup)                                      atomic install
  writes discovery.json
```

The client is given a **domain** at install time. It fetches
`<domain>/discovery.json` (untrusted — location/cadence only) to learn the
manifest URL, then verifies the manifest against its **compiled-in** pinned keys.
So a host move needs no rebuild, and a forged discovery.json can at worst cause a
missed update, never a key injection. See "Runtime location" below.

### Trust anchor — `pinned_signers`

Two ed25519 public keys, embedded at build time via `go:embed`:

- `ixion@YubiKey5-gpg` — YubiKey PGP applet, exposed to SSH via gpg-agent. Daily signing.
- `ixion@SecureBackup` — offline ed25519 key. Recovery and signer rotation.

A manifest is accepted if validly signed by **either** key (and that key is not
revoked). Changing the anchor means editing `pinned_signers` and rebuilding +
re-preloading binaries.

### Signature format — SSHSIG

Manifests are signed with `ssh-keygen -Y sign -n file` (namespace `file`),
producing an OpenSSH `SSHSIG`. The updater verifies SSHSIG **natively in Go**
(`verify.go`), reducing the trust path to a single `crypto/ed25519.Verify`. This
is why there is no dependency on a system `ssh-keygen` — critical for Windows and
OpenWRT/dropbear, which lack `ssh-keygen -Y verify`. Humans can still verify
manually with `ssh-keygen -Y verify` against an `allowed_signers` built from the
two pinned keys (the generator does exactly this as a pre-publish self-check).

### Manifest — `manifest.json`

```json
{
  "schema": 1,
  "serial": 42,
  "issued_at": "2026-06-25T00:00:00Z",
  "keys": ["ssh-ed25519 AAAA... ixion@YubiKey5-gpg", "..."],
  "disable_signer": "ixion@YubiKey5-gpg"   // optional, see Revocation
}
```

Single-user: a flat key list, no per-principal map. Run the client once per user
(your account, `root`) to give each its own `authorized_keys`. The signature
covers the exact served bytes; the JSON is parsed only **after** it verifies.

### Client state — `~/.ssh/.ssh-keys-updater.state`

```json
{ "serial": 42, "disabled": { "SHA256:...": true } }
```

- `serial` — highest accepted serial; the updater refuses anything not strictly
  greater (anti-rollback). A lost state file resets to "accept current" — replay
  protection is per-client and within its lifetime, which is sufficient.
- `disabled` — revoked signer fingerprints, honored forever regardless of serial.

## Update cycle (`ssh-keys-updater run`)

1. Fetch `manifest.json` + `.sig` (HTTPS; TLS is hygiene only — the signature is
   the authority. `-insecure-tls` exists for CA-less targets).
2. Verify SSHSIG against a pinned, non-revoked signer. Fail → stop, touch nothing.
3. Parse manifest. `serial > stored`? else stop (rollback).
4. If `disable_signer` is present, record that signer as revoked (it names the
   *other* key; a key cannot disable itself).
5. Render `managed key block` + the local file **verbatim**.
6. Atomic write (temp + rename, mode 0600) over `authorized_keys`; persist state.

On **any** failure the existing `authorized_keys` is left untouched — a hostile
or corrupt manifest can at worst fail to *add* a key; it can never remove access.

### Local file

`~/.ssh/authorized_keys_local` is concatenated verbatim after the managed block
and is never parsed or validated — it holds LAN/forced-command keys. Final file:

```
# Managed by ssh-keys-updater ...
<verified keys from manifest>

# --- appended from .../authorized_keys_local ---
<local file, byte-for-byte>
```

## Revocation

**A login key:** remove it from `keys.list`, re-sign (serial bumps), publish.
Clients drop it next run; the serial blocks replay of the pre-removal manifest.

**A signing key (the anchor):** the dangerous case — e.g. YubiKey stolen. Sign a
manifest with `disable_signer: "ixion@YubiKey5-gpg"` using the **offline backup
key** (`sign-keys.sh --disable ixion@YubiKey5-gpg --key backup`). Every client
permanently stops trusting YubiKey-signed manifests. The thief cannot undo this:
disabling a signer requires the *other* key, and the revocation is persisted and
serial-protected (verified end-to-end in the self-tests). This is TUF root
rotation, minified to the two-key case — no online trust, no keyservers.

## Bootstrap (preloading)

Security rests on the pinned key arriving out-of-band. The binary has the anchor
compiled in, so:

1. `./release.sh` cross-compiles `dist/` for every target.
2. Move the right binary to a host over a channel you already trust (an existing
   SSH session, USB) — or download it and verify by SHA-256 / attestation.
3. `./ssh-keys-updater install <domain>` — fetches `<domain>/discovery.json`
   (printed for confirmation on first use), saves the resolved location next to
   `authorized_keys`, registers the periodic job, and runs once.

The binary **never** downloads itself from the website; only discovery.json and
the tiny signed manifest are fetched, on each scheduled run (default every 15 min
with random splay so many hosts don't hit the server in a synchronized burst).

## Runtime location (discovery)

The deployment location is **not** compiled in — only the signing keys are. The
client takes a domain argument and resolves the manifest like so:

- `-manifest-url URL` (advanced) → use it directly, skip discovery.
- a domain → fetch `<domain>/discovery.json`; on first use it's printed in full
  and (on a terminal) confirmed. The resolved location is saved to
  `.ssh-keys-updater.conf` next to `authorized_keys`.
- no domain → read that saved config; re-fetch discovery to follow relocations,
  falling back to the last-known manifest URL if discovery is unreachable.
- nothing saved + a terminal → SSH-style prompts (domain, or manifest URL if
  discovery fails). Scheduled (`-scheduled`) runs never prompt.

`discovery.json` is fetched from the untrusted site, so it is **location and
cadence only** — interval/splay are clamped to [1m, 24h], and the manifest it
names still must carry a valid signature from a compiled-in pinned key. Worst
case from a forged/again discovery.json: a missed update, never key injection.
This is what lets the *same binary* survive a host move (as happened moving from
Cloudflare Pages to GitHub Pages): just re-run with the new domain.

## Reproducible builds & CI

Binaries are **not** committed — they'd bloat git history on every Go bump. The
Pages workflow (`.github/workflows/static.yml`) builds them on each deploy and
publishes only the page, the signed manifest, and the fresh `bin/`. This is safe
because the build is **reproducible**: `CGO_ENABLED=0`, `-trimpath`, the only
`-ldflags` value is the version string (no baked URL/identity any more), no
external Go modules, and the Go version pinned in `go.mod` (CI uses
`go-version-file`). The same source + version yields
byte-identical binaries on any host, so the SHA-256 you record from a local
`release.sh` matches what CI serves. The out-of-band hash check, not the build
host, remains the trust anchor for the binary. Tag releases so a local build and
the CI build resolve the same `version` string (else the embedded version
differs and so does the hash).

## Platforms

| Target | Build | Scheduler |
|---|---|---|
| macOS arm64/amd64 | `darwin/*` | launchd (LaunchAgent, or LaunchDaemon as root) |
| Linux arm64/amd64 | `linux/*` | systemd timer if present, else `crontab` |
| Windows arm64/amd64 | `windows/*` | Scheduled Task (`schtasks`) |
| OpenWRT ramips | `linux/mipsle`, `GOMIPS=softfloat` | `/etc/crontabs/root` (busybox cron) |

All binaries are static (`CGO_ENABLED=0`), ~5.6–6.7 MB. For very small ramips
flash, compress with `upx --best` (optional).

### Per-platform install target (auto-detected; override with `-authorized-keys`)

| Platform | Default `authorized_keys` path | Notes |
|---|---|---|
| Linux (generic) | `~/.ssh/authorized_keys` | per-user |
| OpenWRT (ramips) | `/etc/dropbear/authorized_keys` | dropbear's location; persisted in `/overlay`, survives sysupgrade. The LuCI **System → SSH-Keys** page is just an editor for this same file — there is **no uci entry** for key content, so writing the file is all that's needed and the UI reflects it. |
| macOS | `~/.ssh/authorized_keys` | per-user (LaunchAgent), or run as root for a LaunchDaemon |
| Windows (admin acct) | `%ProgramData%\ssh\administrators_authorized_keys` | Windows OpenSSH uses ONE file for all admins and ignores `~/.ssh` for them. The updater also resets the ACL (`icacls`: inheritance off, grant only `SYSTEM` + `Administrators`) — required or sshd silently refuses the file. The scheduled task is registered to run as **SYSTEM** so the scheduled run can write it. |
| Windows (non-admin) | `%USERPROFILE%\.ssh\authorized_keys` | per-user |

All paths were validated end-to-end on real hardware (OpenWRT 24.10 MT7621 router;
Windows 10 22H2 admin account) against a YubiKey-signed manifest: signature
verified, file installed, local file appended, ACL hardened, SSH login confirmed.

## Files

```
<repo root, served at the Pages URL>/
  index.html         generated self-contained page (served at /)
  discovery.json     PUBLIC location descriptor (manifest URL, cadence, identity)
  keys.list          source key list (human-edited) the manifest is built from
  README.md          adopter guide
  manifest.json      published signed manifest          } generated by sign-keys.sh
  manifest.json.sig  detached SSHSIG                      }
  CNAME              custom domain for GitHub Pages (ssh.illixion.com)
  bin/               binaries + SHA256SUMS — built by Pages CI on deploy, gitignored
  updater/
    config.env       deployment config (base URL, identity, repo, cadence, source list)
    *.go             updater (pure stdlib: no external module deps)
    discovery.go     fetch/parse discovery.json · resolve.go  location resolution
    location.go      persisted .ssh-keys-updater.conf · prompt.go  interactive prompts
    pinned_signers   embedded trust anchor (the signing public keys)
    page.tmpl.html   self-contained page template (gen-page fills it)
    generate/sign-keys.sh   build + sign + self-verify; write discovery.json + page
    release.sh       cross-compile matrix -> dist/ (+ SHA256SUMS); bakes only version
    DESIGN.md        this file · INSTALL.md  per-platform install
```

## Commands

```
ssh-keys-updater run          # one fetch+verify+install cycle
ssh-keys-updater install      # schedule periodic checks + run once (-interval, -splay)
ssh-keys-updater uninstall    # remove the schedule
ssh-keys-updater verify M S   # offline-verify a manifest+sig pair
ssh-keys-updater print-pins   # show pinned signer fingerprints
```
