# Installing the updater (bootstrap)

The updater binary has the **trust anchor** (the signing public keys) compiled
in. Getting an authentic binary onto a machine is the one step that must not be
trusted blindly to the website — once it's there, everything else is verified by
signature. Two ways to bootstrap:

- **A — out-of-band copy (best):** `scp` from a machine you already trust, or a
  USB stick. Nothing to verify; the channel is trusted.
- **B — download + verify hash:** pull the binary from the website, then check
  its SHA-256 against a value you carry **independently** — a copy on another
  device or a mobile note. The website is untrusted, so the *hash comparison*, not
  the download, is what makes this safe. This is the path to use when you're at a
  fresh machine's console with only a physical keyboard and type the URL by hand.

## One-time: record the hashes

After `./release.sh`, `dist/SHA256SUMS` lists the SHA-256 of every binary. Store
those values somewhere you control out-of-band — a password manager or a mobile
note you can read from your phone while typing on the target machine. Those are
the numbers you compare against on each new install. (Builds use `-trimpath` and
fixed `-ldflags`, so they're reproducible: the same source + version yields the
same hash.)

## Quick install (download → verify → install)

Replace the target suffix with your platform. Compare the printed hash to your
noted value **before** running the binary. Hex is case-insensitive, so the
uppercase output of Windows tools matches the lowercase output of the Unix ones.

### macOS / Linux

```sh
URL=https://illixion.github.io/bin/ssh-keys-updater-macos-arm64    # pick your target
curl -fLo sku "$URL"
shasum -a 256 sku        # macOS   ── compare to your noted SHA-256
sha256sum  sku           # Linux   ──
chmod +x sku && ./sku install
```

### OpenWRT (ramips)

```sh
URL=https://illixion.github.io/bin/ssh-keys-updater-openwrt-ramips
uclient-fetch -O /tmp/sku "$URL"   # or: wget -O /tmp/sku "$URL"
sha256sum /tmp/sku                  # busybox ── compare to your noted SHA-256
chmod +x /tmp/sku && /tmp/sku install
```

Installs to `/etc/dropbear/authorized_keys` and a cron entry; survives sysupgrade.

### Windows (PowerShell, from an **elevated** prompt)

```powershell
$u = "https://illixion.github.io/bin/ssh-keys-updater-windows-amd64.exe"
curl.exe -fLo sku.exe $u
certutil -hashfile sku.exe SHA256          # built-in, no install ── compare
# or:  Get-FileHash sku.exe -Algorithm SHA256
.\sku.exe install
```

`certutil` is built into Windows, so it works on a bare machine with only a
keyboard. Run elevated: the admin keys file lives in `C:\ProgramData\ssh` and the
scheduled task is registered to run as SYSTEM.

## Manual hash comparison

A SHA-256 is 64 hex characters. Compare the **whole** string against your noted
value — eyeballing it end to end is tedious but is the actual security check. If
you must triage quickly, at minimum verify the first 8 and last 8 characters
match, then do the full compare before trusting the binary on anything important.

## Verify build provenance (optional, complementary)

Every published binary carries a signed SLSA build attestation proving it was
produced by this repo's GitHub Actions workflow from a specific commit. If you
have the `gh` CLI you can check it without having pre-recorded a hash:

```sh
gh attestation verify ssh-keys-updater-macos-arm64 --repo illixion/illixion.github.io
```

This is **defense-in-depth, not a replacement** for the out-of-band hash. The
attestation is minted by GitHub, so it trusts GitHub; the hash you carry on a
separate device is the one check that survives even a compromise of this repo's
host. Use both: provenance for convenience, the recorded hash as the backstop.

## After install

`<binary> install` schedules periodic checks and performs one immediately. Verify and
inspect anytime:

```sh
<binary> print-pins     # show the pinned signer fingerprints baked in
<binary> run            # force an update now
```
