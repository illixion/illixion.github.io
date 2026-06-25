package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"
)

// Config holds the resolved runtime settings for a single update run.
type Config struct {
	ManifestURL    string
	AuthorizedKeys string // target file, e.g. ~/.ssh/authorized_keys
	LocalFile      string // appended verbatim, e.g. ~/.ssh/authorized_keys_local
	InsecureTLS    bool   // skip TLS verification (safe: the signature gates content)
	Timeout        time.Duration
	Splay          time.Duration // max random pre-fetch delay (traffic desync)
}

func (c Config) sigURL() string { return c.ManifestURL + ".sig" }

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

// runUpdate performs one fetch → verify → install cycle. On any verification or
// trust failure it returns an error and leaves authorized_keys untouched, so a
// hostile or corrupt manifest can never remove access or inject a key.
func runUpdate(cfg Config) error {
	pinned, err := loadPinnedSigners()
	if err != nil {
		return err
	}
	state, err := loadState(cfg.AuthorizedKeys)
	if err != nil {
		return fmt.Errorf("loading state: %w", err)
	}

	client := httpClient(cfg)
	manifestBytes, err := fetch(client, cfg.ManifestURL)
	if err != nil {
		return fmt.Errorf("fetching manifest: %w", err)
	}
	sigBytes, err := fetch(client, cfg.sigURL())
	if err != nil {
		return fmt.Errorf("fetching signature: %w", err)
	}

	// 1. Signature must verify against a pinned, non-revoked signer.
	signer, err := VerifySSHSIG(manifestBytes, sigBytes, pinned, state.Disabled)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	logf("manifest signed by %s (%s)", signer.Comment, signer.Fingerprint)

	// 2. Parse only after the bytes are trusted.
	m, err := parseManifest(manifestBytes)
	if err != nil {
		return err
	}

	// 3. Anti-rollback: serial must strictly advance.
	if m.Serial <= state.Serial {
		return fmt.Errorf("manifest serial %d is not newer than installed serial %d; refusing (rollback protection)", m.Serial, state.Serial)
	}

	// 4. Apply a signer revocation if the manifest carries one. This is trusted
	//    because we already proved the manifest is signed by a pinned signer;
	//    revoking the *other* key cannot be done by that key itself.
	if m.DisableSigner != "" {
		target, err := resolveSigner(m.DisableSigner, pinned)
		if err != nil {
			return fmt.Errorf("processing disable_signer: %w", err)
		}
		if target.Fingerprint == signer.Fingerprint {
			return fmt.Errorf("manifest tries to disable its own signer %s; refusing", signer.Comment)
		}
		if !state.Disabled[target.Fingerprint] {
			logf("REVOKING signer %s (%s) per manifest disable_signer", target.Comment, target.Fingerprint)
			state.Disabled[target.Fingerprint] = true
		}
	}

	// 5. Build the file: verified key block, then the local file verbatim.
	content := m.authorizedKeysContent()
	local, err := readLocalFile(cfg.LocalFile)
	if err != nil {
		return fmt.Errorf("reading local file: %w", err)
	}
	if local != "" {
		content += "\n# --- appended from " + cfg.LocalFile + " ---\n" + local
		if !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
	}

	// 6. Atomic install, then persist advanced state.
	if err := atomicWrite(cfg.AuthorizedKeys, []byte(content), 0o600); err != nil {
		return fmt.Errorf("writing authorized_keys: %w", err)
	}
	// Enforce platform-specific permissions (no-op on Unix; required ACL on the
	// Windows administrators_authorized_keys file, else sshd ignores it).
	if err := secureKeyFile(cfg.AuthorizedKeys); err != nil {
		logf("warning: could not secure %s: %v", cfg.AuthorizedKeys, err)
	}
	state.Serial = m.Serial
	if err := saveState(cfg.AuthorizedKeys, state); err != nil {
		return fmt.Errorf("saving state: %w", err)
	}

	logf("installed serial %d: %d key(s) -> %s", m.Serial, len(m.Keys), cfg.AuthorizedKeys)
	return nil
}

// readLocalFile returns the contents of the local key file, or "" if absent.
// The file is never parsed or validated — it holds the user's LAN/forced-command
// keys and is concatenated verbatim after the managed block.
func readLocalFile(path string) (string, error) {
	if path == "" {
		return "", nil
	}
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
	req.Header.Set("User-Agent", fmt.Sprintf("ssh-keys-updater/%s (+%s)", version, defaultBaseURL))
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
