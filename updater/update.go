package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// appendMarkerPrefix begins the line that separates the managed key block from
// the verbatim local file. Drift detection splits on it so edits to the local
// file never look like tampering with the managed block.
const appendMarkerPrefix = "\n# --- appended from "

// managedPortion returns the managed key block — everything before the appended
// local file — from a full authorized_keys body. Identical on the write path and
// the read-back path, so their hashes are comparable.
func managedPortion(content string) string {
	if i := strings.Index(content, appendMarkerPrefix); i >= 0 {
		return content[:i]
	}
	return content
}

func hashManaged(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// checkManagedDrift logs (does not repair) if the managed block on disk differs
// from what the updater last wrote. Tamper-evidence only — see DESIGN.md.
func checkManagedDrift(authorizedKeys string, sc *Sidecar) {
	if sc.ManagedHash == "" {
		return // nothing recorded yet (fresh install)
	}
	b, err := os.ReadFile(authorizedKeys)
	if err != nil {
		return // missing/unreadable: nothing to compare against
	}
	if hashManaged(managedPortion(string(b))) != sc.ManagedHash {
		logf("WARNING: managed authorized_keys block changed outside ssh-keys-updater (since serial %d); it will be re-asserted from the next verified manifest", sc.State.Serial)
	}
}

// Config holds the resolved runtime settings for a single update run.
type Config struct {
	ManifestURL    string
	AuthorizedKeys string // target file, e.g. ~/.ssh/authorized_keys
	InsecureTLS    bool   // skip TLS verification (safe: the signature gates content)
	Timeout        time.Duration
}

func (c Config) sigURL() string { return c.ManifestURL + ".sig" }

// localFile is the operator's hand-maintained key file, always
// authorized_keys_local beside the managed file. Derived rather than
// configured, so every invocation (scheduled, manual, self-update) agrees on it
// without having to be told.
func (c Config) localFile() string {
	return filepath.Join(filepath.Dir(c.AuthorizedKeys), "authorized_keys_local")
}

// applySplay sleeps a uniformly random duration in [0, max) before a scheduled
// run, so many hosts checking on the same cadence don't hit the server in a
// predictable burst at :00/:15/:30/:45. No-op when max <= 0 (manual runs).
func applySplay(max time.Duration) {
	if max <= 0 {
		return
	}
	d := time.Duration(rand.Int63n(int64(max)))
	logf("splay: waiting %s before fetch", d.Round(time.Second))
	time.Sleep(d)
}

// runUpdate performs one fetch → verify → install cycle, then (re)assembles
// authorized_keys from the managed block and the local file. The local merge
// happens on every run — also when the serial is unchanged or the fetch fails —
// so edits to authorized_keys_local land on the next tick without a re-sign.
//
// The managed block written is always one this client verified: the manifest
// just fetched, or else the block already on disk, provided it still hashes to
// managed_hash. A hostile or corrupt manifest can never remove access or
// inject a key; a fetch failure only means the managed block stays as it was.
func runUpdate(cfg Config) error {
	pinned, err := effectiveSigners(cfg.AuthorizedKeys)
	if err != nil {
		return err
	}
	if len(pinned) == 0 {
		return fmt.Errorf("no trusted signers (none embedded and none locally accepted); run `install` to accept one")
	}
	sc, err := loadSidecar(cfg.AuthorizedKeys)
	if err != nil {
		return fmt.Errorf("loading sidecar: %w", err)
	}

	// Tamper-evidence: note any out-of-band edit to the managed block since our
	// last write, before this run possibly overwrites it.
	checkManagedDrift(cfg.AuthorizedKeys, sc)

	m, revoke, fetchErr := fetchManifest(cfg, pinned, sc.State)

	var managed string
	switch {
	case fetchErr == nil && m.Serial > sc.State.Serial:
		managed = m.authorizedKeysContent()
	case fetchErr == nil:
		// Same serial: re-render the verified manifest, which also heals any
		// drift in the managed block.
		managed = m.authorizedKeysContent()
		m = nil // nothing new to record
	default:
		var ok bool
		if managed, ok = installedManaged(cfg.AuthorizedKeys, sc); !ok {
			logf("not merging %s: no verified managed block to merge it with", cfg.localFile())
			return fetchErr
		}
		logf("%v; merging %s with the installed managed block", fetchErr, cfg.localFile())
	}

	content, err := assemble(managed, cfg.localFile())
	if err != nil {
		// Unreadable local file: writing without it could lock out its keys.
		return errors.Join(fetchErr, fmt.Errorf("reading local file: %w", err))
	}
	changed, err := writeIfChanged(cfg.AuthorizedKeys, content)
	if err != nil {
		return errors.Join(fetchErr, fmt.Errorf("writing authorized_keys: %w", err))
	}

	newHash := hashManaged(managedPortion(content))
	if m != nil {
		if revoke != nil && !sc.State.Disabled[revoke.Fingerprint] {
			logf("REVOKING signer %s (%s) per manifest disable_signer", revoke.Comment, revoke.Fingerprint)
			sc.State.Disabled[revoke.Fingerprint] = true
		}
		sc.State.Serial = m.Serial
	}
	if m != nil || sc.ManagedHash != newHash {
		sc.ManagedHash = newHash
		if err := saveSidecar(cfg.AuthorizedKeys, sc); err != nil {
			return errors.Join(fetchErr, fmt.Errorf("saving sidecar: %w", err))
		}
	}

	switch {
	case m != nil:
		logf("installed serial %d: %d key(s) -> %s", m.Serial, len(m.Keys), cfg.AuthorizedKeys)
	case changed:
		logf("re-synced %s (serial %d unchanged)", cfg.AuthorizedKeys, sc.State.Serial)
	case fetchErr == nil:
		logf("manifest serial %d already installed; nothing to do", sc.State.Serial)
	}
	return fetchErr
}

// fetchManifest fetches, verifies and parses the manifest, and rejects a
// rollback or an invalid disable_signer. The returned manifest is trusted; its
// serial may equal (not exceed) the installed one. revoke is the signer named
// by disable_signer, if any.
func fetchManifest(cfg Config, pinned []*PinnedKey, state *State) (m *Manifest, revoke *PinnedKey, err error) {
	client := httpClient(cfg)
	manifestBytes, err := fetch(client, cfg.ManifestURL)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching manifest: %w", err)
	}
	sigBytes, err := fetch(client, cfg.sigURL())
	if err != nil {
		return nil, nil, fmt.Errorf("fetching signature: %w", err)
	}

	// 1. Signature must verify against a pinned, non-revoked signer.
	signer, err := VerifySSHSIG(manifestBytes, sigBytes, pinned, state.Disabled)
	if err != nil {
		return nil, nil, fmt.Errorf("signature verification failed: %w", err)
	}
	logf("manifest signed by %s (%s)", signer.Comment, signer.Fingerprint)

	// 2. Parse only after the bytes are trusted.
	m, err = parseManifest(manifestBytes)
	if err != nil {
		return nil, nil, err
	}

	// 3. Anti-rollback: a strictly older serial is a genuine rollback attempt
	// and must fail. An equal serial is the steady state on every scheduled
	// tick — the caller re-renders it but records nothing new.
	if m.Serial < state.Serial {
		return nil, nil, fmt.Errorf("manifest serial %d is older than installed serial %d; refusing (rollback protection)", m.Serial, state.Serial)
	}

	// 4. A signer revocation is trusted because the manifest is signed by a
	//    pinned signer; revoking the *other* key cannot be done by that key
	//    itself. The caller records it when it installs a new serial.
	if m.DisableSigner != "" {
		if revoke, err = resolveSigner(m.DisableSigner, pinned); err != nil {
			return nil, nil, fmt.Errorf("processing disable_signer: %w", err)
		}
		if revoke.Fingerprint == signer.Fingerprint {
			return nil, nil, fmt.Errorf("manifest tries to disable its own signer %s; refusing", signer.Comment)
		}
	}
	return m, revoke, nil
}

// installedManaged returns the managed block currently on disk, but only if it
// still hashes to what this client last wrote from a verified manifest — so a
// merge without a fresh manifest never re-asserts a tampered block.
func installedManaged(authorizedKeys string, sc *Sidecar) (string, bool) {
	if sc.ManagedHash == "" {
		return "", false
	}
	b, err := os.ReadFile(authorizedKeys)
	if err != nil {
		return "", false
	}
	managed := managedPortion(string(b))
	return managed, hashManaged(managed) == sc.ManagedHash
}

// assemble renders the final file: the managed block, then the local file
// verbatim behind the marker (omitted when the local file is absent or empty).
func assemble(managed, localPath string) (string, error) {
	local, err := readLocalFile(localPath)
	if err != nil || local == "" {
		return managed, err
	}
	content := managed + appendMarkerPrefix + localPath + " ---\n" + local
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content, nil
}

// writeIfChanged atomically replaces authorized_keys (mode 0600) unless it
// already holds exactly content, so the steady-state tick touches nothing.
func writeIfChanged(path, content string) (bool, error) {
	if cur, err := os.ReadFile(path); err == nil && string(cur) == content {
		return false, nil
	}
	if err := atomicWrite(path, []byte(content), 0o600); err != nil {
		return false, err
	}
	// Enforce platform-specific permissions (no-op on Unix; required ACL on the
	// Windows administrators_authorized_keys file, else sshd ignores it).
	if err := secureKeyFile(path); err != nil {
		logf("warning: could not secure %s: %v", path, err)
	}
	return true, nil
}

// readLocalFile returns the contents of the local key file, or "" if absent.
// The file is never parsed or validated — it holds the user's LAN/forced-command
// keys and is concatenated verbatim after the managed block.
func readLocalFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func httpClient(cfg Config) *http.Client {
	tr := &http.Transport{}
	if cfg.InsecureTLS {
		// Acceptable by design: the SSHSIG signature is the sole authority over
		// content, so TLS adds only transport hygiene. This flag exists for
		// minimal targets (e.g. OpenWRT) lacking a CA bundle.
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{Timeout: cfg.Timeout, Transport: tr}
}

func fetch(client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", fmt.Sprintf("ssh-keys-updater/%s", version))
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB cap
}
