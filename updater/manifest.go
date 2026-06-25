package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Manifest is the signed payload published at the manifest URL. The signature
// (.sig file) is computed over the exact bytes of the manifest as served, so
// this struct is only parsed *after* the signature verifies.
type Manifest struct {
	Schema   int    `json:"schema"`
	Serial   uint64 `json:"serial"`
	IssuedAt string `json:"issued_at"`

	// Keys is the authorized_keys content this single-user client should
	// install (one entry per line in the output file).
	Keys []string `json:"keys"`

	// DisableSigner, when set, names a pinned signer (by comment or
	// "SHA256:..." fingerprint) to permanently revoke on this client. Honored
	// only because the manifest carrying it is, by definition, signed by the
	// *other* pinned key — a compromised key cannot un-revoke itself. The
	// revocation is persisted in client state and survives rollback.
	DisableSigner string `json:"disable_signer,omitempty"`
}

const manifestSchema = 1

func parseManifest(b []byte) (*Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("parsing manifest: %w", err)
	}
	if m.Schema != manifestSchema {
		return nil, fmt.Errorf("manifest schema %d != supported %d", m.Schema, manifestSchema)
	}
	if m.Serial == 0 {
		return nil, fmt.Errorf("manifest serial must be > 0")
	}
	if len(m.Keys) == 0 && m.DisableSigner == "" {
		return nil, fmt.Errorf("manifest has no keys and no disable_signer; refusing to install an empty key set")
	}
	for i, k := range m.Keys {
		if _, err := parseAnyPublicKey(k); err != nil {
			return nil, fmt.Errorf("manifest key %d is not a valid SSH public key: %w", i, err)
		}
	}
	return &m, nil
}

// authorizedKeysContent renders the verified key block. The caller appends the
// untouched local file after this.
func (m *Manifest) authorizedKeysContent() string {
	var b strings.Builder
	b.WriteString("# Managed by ssh-keys-updater — do not edit. Source: signed manifest.\n")
	fmt.Fprintf(&b, "# serial=%d issued_at=%s\n", m.Serial, m.IssuedAt)
	for _, k := range m.Keys {
		b.WriteString(strings.TrimSpace(k))
		b.WriteByte('\n')
	}
	return b.String()
}
