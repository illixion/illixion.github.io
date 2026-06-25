# Self-hosted, end-to-end-signed SSH key sync

Publish your SSH `authorized_keys` from a web page and have your machines pull
updates automatically — **without trusting the web server**. Every update is
verified against a hardware-backed signing key before it touches
`authorized_keys`, so a compromised host, CDN, DNS, or TLS cert cannot inject a
key or roll you back to an old one.

This is the system that runs at <https://illixion.github.io>. You can adopt it for
your own keys; it's a single static Go binary plus two shell scripts.

## Why not just `curl https://example.com/keys >> authorized_keys`?

Because that trusts the web server completely. If the site (or its CDN/host)
serves attacker bytes with `200 OK`, you've authorized the attacker. The whole
point here is to remove that trust:

- The website is a **dumb, untrusted pipe**. It only carries a signed blob.
- Trust lives in a **signing key on a YubiKey** (plus an offline backup), whose
  public half is **compiled into the updater** and delivered out-of-band.
- The updater verifies the signature locally (no dependency on system crypto
  tools — works on Windows and OpenWRT/dropbear too) and only then installs.

See [updater/DESIGN.md](updater/DESIGN.md) for the full threat model.

## How it works

```
Your Mac (trusted)               your website (UNTRUSTED)          your machines
──────────────────               ────────────────────────         ─────────────
generate/sign-keys.sh   ─push─►  /manifest.json       ─GET─►   ssh-keys-updater
  build manifest                 /manifest.json.sig            (pinned keys
  sign with YubiKey                                                 compiled in)
  + self-verify                                                    verify → check
                                                                   serial → atomic
                                                                   install
```

- **manifest.json** — a small signed JSON: `serial`, `issued_at`, the `keys`
  list, and an optional `disable_signer` for revoking a compromised signing key.
- **manifest.json.sig** — a detached `SSHSIG` (`ssh-keygen -Y sign`).
- **serial** — monotonic; the updater refuses anything not strictly newer, so a
  hostile CDN can't replay an old manifest that still lists a removed key.
- **two pinned signers** — a daily one (YubiKey) and an offline backup. Either
  can sign; the backup can *revoke* the YubiKey remotely (and a stolen key can't
  un-revoke itself). No expiry — keys are hardware-backed.

## Layout

```
<repo root, served at your Pages URL>/
  index.html            generated page (served at /)
  manifest.json[.sig]   the signed, published artifacts
  bin/                  binaries + SHA256SUMS — built by CI on deploy, NOT committed
  README.md             this file
  keys.list             YOUR source key list (authorized_keys format) — edit + re-sign
  updater/
    config.env          deployment config: base URL, page identity, source list
    *.go                the updater (pure stdlib, no external deps)
    pinned_signers      YOUR trust anchor: the signing public keys
    page.tmpl.html      self-contained page template (gen-page fills it)
    generate/sign-keys.sh   build + sign + self-verify the manifest (+ page)
    release.sh          cross-compile all targets
    DESIGN.md           threat model & internals
    INSTALL.md          per-platform download/verify/install
```

## Adopt it for your own keys

1. **Make a signing keypair on hardware**, plus an offline backup keypair.
   Plain `ed25519` keys (the verifier is a single `ed25519.Verify`):
   ```sh
   ssh-keygen -t ed25519 -C you@backup -f securebackup_ed25519   # keep offline
   # your YubiKey's ed25519 (PGP/PIV/FIDO) exposed to ssh-agent is the daily signer
   ```

2. **Pin them.** Put both public keys in [updater/pinned_signers](updater/pinned_signers),
   one per line, `ssh-ed25519 AAAA... comment`. This is the trust anchor baked
   into every binary — get it right.

3. **Configure.** Edit [updater/config.env](updater/config.env) — your public
   base URL, page title/handle, and the source key list. That one file feeds
   both the binary build (baked in via `-ldflags`) and the signer/page generator.

4. **Record the binary hashes out-of-band.** `cd updater && ./release.sh v1`
   cross-compiles all targets and writes `dist/SHA256SUMS`. Save those numbers
   somewhere you control (an iOS note). The Pages CI rebuilds the *same bytes*
   on deploy (reproducible: `-trimpath`, fixed `-ldflags`, Go pinned via
   `go.mod`), so what's served matches what you recorded. See INSTALL.md.

5. **List the keys to authorize** in [keys.list](keys.list) (one SSH public key
   per line), then **sign:** `generate/sign-keys.sh` builds `manifest.json`,
   signs it through your agent (auto-finds the pinned signer; touch your key),
   self-verifies, and regenerates `index.html`.

6. **Publish:** commit and push. CI builds the binaries and deploys — your page
   is live at your Pages URL (this deployment: <https://illixion.github.io>).
   Binaries are never committed, so the repo stays small.

7. **Install on each machine:** download the binary, verify its SHA-256 against
   your out-of-band value, run `./ssh-keys-updater install`. Full per-platform
   steps in [updater/INSTALL.md](updater/INSTALL.md).

## Verifying a downloaded binary

The binary carries the trust anchor compiled in, so confirming you have an
authentic copy is the one step that matters. The website is untrusted — trust
the verification, not the download. Two independent ways, strongest first:

### 1. Out-of-band SHA-256 (the backstop)

Build the binaries yourself once and record their hashes somewhere you control
(a password manager, an iOS note). Builds are reproducible — `CGO_ENABLED=0`,
`-trimpath`, fixed `-ldflags` from `config.env`, Go pinned in `go.mod`, zero
external modules — so your local hashes match what CI serves byte-for-byte:

```sh
cd updater && ./release.sh            # builds dist/ for every target
cat dist/SHA256SUMS                   # <- record these out-of-band
```

On a new machine, after downloading, compare:

```sh
shasum -a 256 <file>                  # macOS
sha256sum <file>                      # Linux / OpenWRT
certutil -hashfile <file> SHA256      # Windows (built in)
```

This check survives even a full compromise of GitHub/the host, because the
reference value lives only with you. To re-derive the canonical hashes at any
time, build the tagged release: `git checkout v1.0.0 && cd updater && ./release.sh`.

### 2. Build provenance attestation (convenient, defense-in-depth)

Every published binary has a signed SLSA attestation proving it was built by this
repo's GitHub Actions workflow from a specific commit. With the `gh` CLI you can
verify without any pre-recorded hash:

```sh
gh attestation verify ssh-keys-updater-macos-arm64 --repo illixion/illixion.github.io
```

This is great for first installs and adopters, but it is minted by GitHub — so it
trusts GitHub. Treat it as defense-in-depth; the out-of-band hash (#1) remains
the ultimate check. The manifest itself is separately signed by a hardware key,
a stronger root than either.

## Day-to-day

- **Add/remove a key:** edit the source list, run `sign-keys.sh` (serial bumps),
  push. Machines pick it up within the check interval (default every 15 min,
  with random splay so traffic isn't synchronized).
- **Revoke the YubiKey (lost/stolen):**
  `sign-keys.sh --disable <comment-of-yubikey> --key-file <backup-private-key>`, push. Every client
  permanently stops trusting it.

## Commands

```
ssh-keys-updater run          # one fetch+verify+install
ssh-keys-updater install      # schedule periodic runs + run once (-interval, -splay)
ssh-keys-updater uninstall    # remove the schedule
ssh-keys-updater verify M S   # offline-verify a manifest+sig
ssh-keys-updater gen-page     # render the self-contained page (-base-url -title -handle -out)
ssh-keys-updater print-pins   # show pinned signer fingerprints
```

Licensed for anyone to adopt. No warranty — you own your keys.
