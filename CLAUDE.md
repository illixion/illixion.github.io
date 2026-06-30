# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

This repo is **both** a GitHub Pages site (served at https://ssh.illixion.com) and the source for `ssh-keys-updater`, a Go tool that distributes an SSH `authorized_keys` file with end-to-end signature verification. The website is treated as a **fully untrusted pipe**: trust lives only in two ed25519 signing keys compiled into the client. Read [README.md](README.md) and [updater/DESIGN.md](updater/DESIGN.md) for the threat model before changing anything security-relevant.

## The one workflow that matters: re-signing keys

Almost every change to authorized keys or pins goes through `sign-keys.sh`, which rebuilds + signs the manifest, writes `discovery.json`, and regenerates the page:

```sh
# 1. Edit the human source of truth:
#      keys.list             — the SSH keys to authorize (authorized_keys format)
#      updater/pinned_signers — the trust anchor (signing public keys)
#      updater/config.env     — base URL, identity, cadence
# 2. Re-sign (requires the YubiKey signer loaded in an ssh-agent/gpg-agent; touch when it blinks):
cd updater/generate && ./sign-keys.sh
# 3. Review, then commit + push. CI builds binaries and deploys.
```

`sign-keys.sh` flags: `--signer <comment|index>` (pick which pinned signer), `--key-file <priv>` (offline backup key, no agent), `--gpg-agent` (force gpg-agent's ssh socket), `--disable <comment> --key-file <backup>` (revoke a signing key — must be signed by the *other* pin).

**Serial is monotonic and auto-incremented** from the current `manifest.json`. Clients reject any manifest whose serial isn't strictly greater (anti-rollback). To **reset the serial** (only valid before deployment to any host), set `"serial"` in `manifest.json` to one less than the target, then re-sign — e.g. set it to `0` to get back to `1`.

### Generated vs. source files — never hand-edit the generated ones

`sign-keys.sh` (re)writes these; edit the source and re-sign instead:
- `manifest.json`, `manifest.json.sig` — built from `keys.list`, signed.
- `discovery.json` — built from `config.env`.
- `index.html` — rendered from [updater/page.tmpl.html](updater/page.tmpl.html) via `go run . gen-page`. The page embeds the pinned-signer key blobs **and** their SHA256 fingerprints (`{{SIGNERS_ALLOWED}}` / `{{SIGNERS_FP}}`); editing the key in `index.html` by hand leaves a stale fingerprint, so always regenerate.

## Build & test

```sh
cd updater
go build .                              # build for the host
./release.sh [version]                  # cross-compile all 7 targets -> dist/ + SHA256SUMS
./release.sh --publish [version]        # also stage into ../bin/ for the site (CI does this)
go run . print-pins                     # show pinned fingerprints baked into this build
go run . gen-page -base-url URL -title T -handle H -repo R -out index.html
go run . verify manifest.json manifest.json.sig   # offline-verify the signed pair
```

- **No automated test suite** — there are no `*_test.go` files. Verification is the self-verify step inside `sign-keys.sh` (`ssh-keygen -Y verify` against `pinned_signers`) plus manual hardware validation. `go vet ./...` and `go build` are the available checks.
- **Reproducible builds are a hard requirement.** `CGO_ENABLED=0`, `-trimpath`, the only `-ldflags` value is `main.version`, zero external Go modules (no `go.sum`), Go pinned in `updater/go.mod`. The same source + version tag must yield byte-identical binaries so the out-of-band SHA-256 matches what CI serves. Do not introduce external dependencies or anything that bakes host/time/path into the binary. Tag releases so local and CI builds resolve the same `version`.
- Binaries are **never committed** (`bin/`, `dist/` are gitignored); CI in [.github/workflows/static.yml](.github/workflows/static.yml) builds them on every push to `main` and deploys page + manifest + fresh `bin/` to Pages, with SLSA build-provenance attestation.

## Client architecture (`updater/*.go`, package `main`, pure stdlib)

The two design pillars: **trust is compile-time, location is runtime.**

- **Trust anchor** — [pinned_signers](updater/pinned_signers) is `go:embed`-ed into every binary ([pin.go](updater/pin.go)); normally two ed25519 keys (a daily YubiKey signer + an offline backup). The effective trust set is `pinned_signers` ∪ **locally-accepted pins** (`effectiveSigners` in pin.go) — the latter let an adopter pin their own signer at install time without rebuilding, so `pinned_signers` MAY be empty (a neutral build). Trust is never sourced from the network; the deployment URL is **not** compiled in.
- **Location resolution** ([resolve.go](updater/resolve.go), [discovery.go](updater/discovery.go), [location.go](updater/location.go), [prompt.go](updater/prompt.go)) — a domain arg → fetch `<domain>/discovery.json` (untrusted; location/cadence only) → save resolved location into the `.ssh-keys-updater.json` sidecar next to `authorized_keys`. This is why a host move (Cloudflare → GitHub Pages) needs no rebuild. A forged discovery.json can at worst cause a missed update, never a key injection.
- **Signature verification** ([verify.go](updater/verify.go), [sshwire.go](updater/sshwire.go)) — SSHSIG is verified **natively in Go**, reducing the trust path to one `crypto/ed25519.Verify`. `parseAndCheckSSHSIG` checks crypto validity against the key embedded in the signature (used at install to show an adopter the fingerprint before pinning); `VerifySSHSIG` adds the trust-set + revocation gate for the run path. The manifest JSON is parsed only *after* the signature verifies.
- **Install-time trust acceptance** (`ensureSignerTrusted` in main.go) — for a non-embedded signer, `install`/`system-install` print the fingerprint and require interactive confirmation (or `-accept-signer SHA256:…`) after OOB verification, then append it to the sidecar's `pins`. Scheduled runs never accept a new signer (fail closed).
- **Update cycle** ([update.go](updater/update.go), [manifest.go](updater/manifest.go), [state.go](updater/state.go)) — fetch → verify SSHSIG against a trusted, non-revoked signer → check `serial` strictly increases → record any `disable_signer` revocation → log managed-block drift vs `managed_hash` → atomically write (temp+rename, mode 0600) the managed block followed by `authorized_keys_local` verbatim → persist state + new `managed_hash`. **On any failure the existing `authorized_keys` is left untouched** — a hostile manifest can fail to add a key but can never remove access.
- **Sidecar** (`~/.ssh/.ssh-keys-updater.json`, [sidecar.go](updater/sidecar.go)) — one per-user JSON holding `{location, state, pins, managed_hash}`. `loadSidecar` migrates the legacy `.ssh-keys-updater.conf`/`.state` files on first load and deletes them. `loadState`/`saveState`/`loadLocation`/`saveLocation` are thin accessors over it.
- **Platform layers** — schedulers ([schedule.go](updater/schedule.go) + `schedule_{darwin,linux,windows}.go`: launchd / systemd-or-cron / schtasks; `runArgs(cfg, exe)` lets `system-install` point the unit at the installed path) and paths ([paths_{linux,windows,other}.go](updater/) incl. `systemBinPath`, [sysinstall.go](updater/sysinstall.go), [secure_{unix,windows}.go](updater/), [fsutil.go](updater/fsutil.go)). Build tags select per-OS files; keep new OS-specific code behind the same tag pattern. Windows admin installs write `administrators_authorized_keys` and must reset its ACL via `icacls` or sshd silently refuses the file.

CLI subcommands (`main.go`): `run`, `install`, `system-install`, `uninstall`, `verify`, `gen-page`, `print-pins`, `version`. Flags and the optional `[domain]` positional may appear in any order.
