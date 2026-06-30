# ssh-keys-updater

End-to-end-signed distribution of an SSH `authorized_keys` file. The website
(Cloudflare, GitHub, DNS, TLS) is treated as a **fully untrusted pipe**: even if
it returns attacker-chosen bytes with `200 OK`, no key of the attacker's
choosing can land in `authorized_keys`. Trust lives only in signing keys that
reach each client over a trusted channel — either **compiled into the binary**
(`pinned_signers`) or **accepted once at install time after out-of-band
fingerprint verification** and then frozen in a local trust file. Trust is
**never sourced from the network during scheduled runs.**

## Threat model

Defended:

- **Malicious `200 OK`** — compromised CDN/host/repo serving attacker content →
  rejected (no valid signature from a pinned key).
- **Replay / rollback** — serving an older but once-valid manifest that still
  lists a since-removed key → rejected (monotonic `serial`).
- **Signing-key compromise** — a stolen signing key → revoke it remotely with
  the *other* pinned key; a stolen key cannot un-revoke itself (revocation is
  persisted and serial-protected).
- **Trust injection via the website** — a forged `discovery.json` (or compromised
  CDN) that *advertises* an attacker's signer → cannot add trust. Discovery's
  advertised signers are a display hint only; trust is added solely by an embedded
  pin or an explicit interactive `install`-time confirmation, and a scheduled run
  **never** accepts a new signer.

The core invariant: **a signer the client was not told to trust — by embedding
or by an explicit, out-of-band-verified `install`-time acceptance — can never
sign a manifest the client accepts.** The accepted set is frozen in a local,
0600 trust file (root-owned for system installs); steady-state runs read trust
from that file and the embedded pins only, never from the network.

Out of scope: local root compromise of a client (can edit the binary, its state,
its local pin file, or `authorized_keys` directly). The trust anchor lives in the
binary and in a root-owned local file, so swapping either is a local-root action,
not a network one.

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

### Trust anchor — embedded pins ∪ locally-accepted pins

A manifest is accepted if validly signed by a **trusted, non-revoked** signer.
The trusted set is the **union** of two sources:

1. **Embedded pins** — `pinned_signers`, `go:embed`-ed at build time. For this
   deployment, two ed25519 public keys:
   - `ixion@YubiKey5-gpg` — YubiKey PGP applet, exposed to SSH via gpg-agent. Daily signing.
   - `ixion@SecureBackup` — offline ed25519 key. Recovery and signer rotation.
2. **Locally-accepted pins** — `.ssh-keys-updater.pins` next to `authorized_keys`
   (0600, root-owned for system installs), holding signer public keys the operator
   accepted interactively at `install` time. Same `authorized_keys` line format as
   `pinned_signers`.

Changing the embedded anchor means editing `pinned_signers` and rebuilding +
re-preloading binaries. Adding a local pin happens at install time (below) and
needs no rebuild.

#### Adopter reuse and neutral builds

So a third party can run **the same binary** against **their own** signer without
recompiling, `pinned_signers` may be **empty** (a "neutral" build). The build
still succeeds; only `run` requires the *effective* set (embedded ∪ local) to be
non-empty — an empty set fails closed.

Establishing trust on a neutral (or differently-pinned) build is **TOFU with
out-of-band verification**, exactly like SSH `known_hosts`:

- At `install`, after resolving the location, the client fetches the manifest +
  signature and **cryptographically validates the signature against the public
  key embedded in the SSHSIG itself** (proves the bytes are self-consistently
  signed), *without* yet trusting that key. It then prints the signer's
  `SHA256:…` fingerprint and comment.
- If that signer is already trusted (embedded or already in the local pin file),
  install proceeds silently — the strong, unchanged path for first-party hosts.
- Otherwise the client requires an **explicit interactive confirmation** of the
  fingerprint (or a matching `-accept-signer SHA256:…` flag). The adopter is
  instructed to compare it out-of-band against the value the deployment publishes
  (its README/release notes) — the **same OOB step, and the same trust weight, as
  the binary's SHA-256**. On confirmation the signer is written to the local pin
  file; from then on it is pinned locally and scheduled runs verify against it.
- A **scheduled** (`-scheduled`) run never accepts a new signer: an unknown signer
  is a hard failure, never a prompt. So the website can advertise whatever it
  likes — trust only ever grows through a human at install time.

This is deliberately **not** a "warn if the signer differs from the baked-in pin"
scheme: for a first-party host a signer mismatch is an attack to fail closed on,
not warn about; for an adopter the baked-in pin is irrelevant, so a per-run
warning would be pure noise and train the user to click through. Trust is binary
(in the effective set or rejected); the only soft moment is the one-time,
OOB-verified install acceptance.

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

### Client sidecar — `~/.ssh/.ssh-keys-updater.json`

A **single** per-user JSON file next to `authorized_keys` (0600; root-owned for
system installs) holds all persisted state. One file per identity, isolated by
directory + ownership — which is exactly the per-user, shared-binary story.

```json
{
  "location": { "discovery_url": "...", "manifest_url": "...", "interval": "15m", "splay": "15m" },
  "state":    { "serial": 42, "disabled": { "SHA256:...": true } },
  "pins":     ["ssh-ed25519 AAAA... adopter@host"],
  "managed_hash": "sha256:..."
}
```

- `location` — where to fetch (discovery/manifest URL, cadence). Convenience only;
  re-fetched each run to follow relocations. Never trust material.
- `state.serial` — highest accepted serial; the updater refuses anything not
  strictly greater (anti-rollback). A lost sidecar resets to "accept current" —
  replay protection is per-client and within its lifetime, which is sufficient.
- `state.disabled` — revoked signer fingerprints, honored forever regardless of
  serial. Revocation applies to **any** trusted signer, embedded or locally-pinned,
  and requires a manifest signed by a *different* trusted signer (so revocation
  needs ≥2 trusted signers — same constraint as the first-party two-key anchor).
- `pins` — adopter-accepted signer public keys in `authorized_keys` line format,
  written after an OOB-verified `install`-time acceptance (see "Adopter reuse").
  Empty for first-party hosts that rely solely on embedded pins. The effective
  trust set used by every verification is `pinned_signers` ∪ `pins`; a `run` fails
  closed if that union is empty.
- `managed_hash` — SHA-256 of the managed key block as last written, used only for
  tamper-evidence (below).

**Migration.** The sidecar supersedes the earlier separate `.ssh-keys-updater.conf`
(location) and `.ssh-keys-updater.state` (state) files. On load, if the unified
JSON is absent but either legacy file is present, the updater reads them, writes
the merged sidecar, and **deletes the legacy files** — a one-time, transparent
upgrade with no user action.

### Tamper-evidence — managed-block drift logging

The client has **no signing key** (trust is one-directional: the Mac/YubiKey signs,
clients only `ed25519.Verify`), so it cannot — and does not — sign `authorized_keys`.
That would also buy nothing: the only actor who can edit `authorized_keys` is local
root, which is **out of scope** and could forge any client-side signature anyway.

What is cheap and honest is **detection**, not prevention. Each run, before
overwriting, the updater isolates the managed block on disk (everything before the
`# --- appended from … ---` marker — so legitimate edits to `authorized_keys_local`
never trip it) and compares its SHA-256 against `managed_hash`. A mismatch is
**logged** as drift ("managed block changed outside ssh-keys-updater since serial
N") and is a fleet-monitoring signal only — the next applied manifest re-asserts the
block. This is explicitly evidence, not a control; it cannot stop the out-of-scope
local-root actor, only surface that the file changed.

## Update cycle (`ssh-keys-updater run`)

1. Fetch `manifest.json` + `.sig` (HTTPS; TLS is hygiene only — the signature is
   the authority. `-insecure-tls` exists for CA-less targets).
2. Verify SSHSIG against a pinned, non-revoked signer. Fail → stop, touch nothing.
3. Parse manifest. `serial > stored`? else stop (rollback).
4. If `disable_signer` is present, record that signer as revoked (it names the
   *other* key; a key cannot disable itself).
5. Render `managed key block` + the local file **verbatim**. Before overwriting,
   compare the on-disk managed block against `managed_hash` and log drift (above).
6. Atomic write (temp + rename, mode 0600) over `authorized_keys`; persist state +
   the new `managed_hash` to the sidecar.

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
3. Install. Two forms:
   - `./ssh-keys-updater install <domain>` — schedules from wherever the binary
     currently sits (its absolute path is baked into the scheduler unit, so don't
     run this from a temp dir you intend to delete).
   - `sudo ./ssh-keys-updater system-install <domain>` — **copies the running
     binary to the canonical system path** (`/usr/local/bin/ssh-keys-updater`,
     `%ProgramFiles%\ssh-keys-updater\` on Windows), logs that path, then
     schedules from the installed copy. This is the recommended form: the
     scheduler references a stable location, so deleting the downloaded binary
     afterwards is harmless. See "System install" below.

   For a first-party host the signer is embedded, so install is silent. For an
   adopter running a neutral/differently-pinned binary, install fetches the
   manifest, validates the signature self-consistently, prints the signer
   fingerprint, and requires an **out-of-band-verified confirmation** (or
   `-accept-signer SHA256:…`) before pinning it locally — see "Adopter reuse"
   above.

The binary **never** downloads itself from the website; only discovery.json and
the tiny signed manifest are fetched, on each scheduled run (default every 15 min
with random splay so many hosts don't hit the server in a synchronized burst).

### System install

`system-install` makes the binary's location stable, fixing the failure mode
where `install` bakes a throwaway path (e.g. `~/Downloads/`) into the scheduler
and a later `rm` silently breaks updates. It:

1. Resolves the canonical per-OS destination (`systemBinPath()`): `/usr/local/bin`
   on macOS/Linux, `/usr/bin` on OpenWRT, `%ProgramFiles%\ssh-keys-updater\` on
   Windows.
2. Requires the privilege to write there (root / Administrator), and refuses
   otherwise with a clear message.
3. Atomically self-copies the running executable to the destination
   (temp + rename in the destination dir, mode 0755, root-owned) and **logs the
   installed path**. If already running from the destination, the copy is skipped
   (idempotent).
4. Schedules using the **destination** path (a system LaunchDaemon / system
   systemd unit / root crontab), not the path it was launched from, then runs once.

Per-user fan-out on a shared system binary: because location, state, and the
local pin file all live next to each user's `authorized_keys`, one system-wide
binary can serve multiple identities — run `install`/`system-install` once per
target account, each accepting its own signer and domain. The binary is shared;
trust and location are per-user.

## Runtime location (discovery)

The deployment location is **not** compiled in — only the signing keys are. The
client takes a domain argument and resolves the manifest like so:

- `-manifest-url URL` (advanced) → use it directly, skip discovery.
- a domain → fetch `<domain>/discovery.json`; on first use it's printed in full
  and (on a terminal) confirmed. The resolved location is saved to the
  `.ssh-keys-updater.json` sidecar next to `authorized_keys`.
- no domain → read that saved config; re-fetch discovery to follow relocations,
  falling back to the last-known manifest URL if discovery is unreachable.
- nothing saved + a **build-time default** (`main.defaultDomain`, baked from
  `config.env`'s `SKU_BASE_URL`) → use it, so `install`/`run` need no argument.
  This is a convenience fallback only: it is consulted *after* a saved config (so
  host moves still need no rebuild), an explicit argument still overrides it, and
  it carries no trust — the manifest it leads to must still verify against a
  trusted signer. Empty in a generic build.
- nothing saved + no default + a terminal → SSH-style prompts (domain, or manifest
  URL if discovery fails). Scheduled (`-scheduled`) runs never prompt.

`discovery.json` is fetched from the untrusted site, so it is **location and
cadence only** — interval/splay are clamped to [1m, 24h], and the manifest it
names still must carry a valid signature from a trusted (embedded or
locally-pinned) key. It MAY carry an optional `signers` array advertising the
deployment's signer fingerprints, but this is a **display hint shown at install
time only** — it is never read as trust and never consulted on a scheduled run.
The client always pins the signer it *actually verified* from the manifest
signature, after OOB confirmation, not whatever discovery claims. Worst case from
a forged discovery.json: a missed update or a bogus fingerprint the human rejects
at install — never key injection.
This is what lets the *same binary* survive a host move (as happened moving from
Cloudflare Pages to GitHub Pages): just re-run with the new domain.

## Reproducible builds & CI

Binaries are **not** committed — they'd bloat git history on every Go bump. The
Pages workflow (`.github/workflows/static.yml`) builds them on each deploy and
publishes only the page, the signed manifest, and the fresh `bin/`. This is safe
because the build is **reproducible**: `CGO_ENABLED=0`, `-trimpath`, the only
`-ldflags` values are `main.version` and `main.defaultDomain` (the latter sourced
from `config.env`'s `SKU_BASE_URL` — a convenience default location, **not** trust
and not a hard location; see "Runtime location"), no external Go modules, and the
Go version pinned in `go.mod` (CI uses `go-version-file`). Both values come from
tracked inputs (a git tag and `config.env`), so the same source + tag + config
yields byte-identical binaries on any host, and the SHA-256 you record from a
local `release.sh` matches what CI serves. The out-of-band hash check, not the build
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
    location.go      Location type · sidecar.go  unified .ssh-keys-updater.json (+legacy migration) · prompt.go  interactive prompts
    pinned_signers   embedded trust anchor (the signing public keys; MAY be empty for a neutral/adopter build)
    page.tmpl.html   self-contained page template (gen-page fills it)
    generate/sign-keys.sh   build + sign + self-verify; write discovery.json + page
    release.sh       cross-compile matrix -> dist/ (+ SHA256SUMS); bakes only version
    DESIGN.md        this file · INSTALL.md  per-platform install
```

## Commands

```
ssh-keys-updater run            # one fetch+verify+install cycle
ssh-keys-updater install        # schedule periodic checks + run once (-interval, -splay, -accept-signer)
ssh-keys-updater system-install # copy binary to the system path, then schedule from there (root)
ssh-keys-updater uninstall      # remove the schedule
ssh-keys-updater verify M S     # offline-verify a manifest+sig pair
ssh-keys-updater print-pins     # show trusted signer fingerprints (embedded + locally-accepted)
```
