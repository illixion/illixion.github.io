package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Minimal SSH wire-format helpers. The SSH wire protocol (RFC 4251 §5) encodes
// a "string" as a uint32 big-endian length followed by that many bytes. We only
// need to read these; we never produce SSH-format output. Keeping this in
// stdlib-only code is what lets the updater compile to a single dependency-free
// static binary for every target (including linux/mipsle for ramips).

var errShortWire = errors.New("ssh wire: truncated buffer")

// readString consumes one length-prefixed string from b, returning its value
// and the remaining bytes.
func readString(b []byte) (val, rest []byte, err error) {
	if len(b) < 4 {
		return nil, nil, errShortWire
	}
	n := binary.BigEndian.Uint32(b[:4])
	if uint64(n) > uint64(len(b)-4) {
		return nil, nil, errShortWire
	}
	return b[4 : 4+n], b[4+n:], nil
}

// sshString returns the wire encoding of a single string (used to rebuild the
// signed-data preamble during verification).
func sshString(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}

// PinnedKey is a trusted signer parsed from an authorized_keys-style line.
type PinnedKey struct {
	Comment     string // e.g. "ixion@YubiKey5-gpg"
	Algo        string // e.g. "ssh-ed25519"
	Wire        []byte // full SSH wire-format public key blob
	Ed25519     []byte // raw 32-byte ed25519 public key
	Fingerprint string // "SHA256:..." (matches `ssh-keygen -lf`)
}

// knownKeyAlgos is the set of public-key algorithms permitted in a manifest's
// installed key list. This is a sanity check on the verified payload, not a
// trust decision (the signature already gated the content) — it stops a typo or
// junk line from landing in authorized_keys.
var knownKeyAlgos = map[string]bool{
	"ssh-ed25519":                        true,
	"sk-ssh-ed25519@openssh.com":         true,
	"ssh-rsa":                            true,
	"ecdsa-sha2-nistp256":                true,
	"ecdsa-sha2-nistp384":                true,
	"ecdsa-sha2-nistp521":                true,
	"sk-ecdsa-sha2-nistp256@openssh.com": true,
}

// parseAnyPublicKey validates that a line is a well-formed SSH public key of a
// known algorithm. Used to vet manifest entries before they are written.
func parseAnyPublicKey(line string) (algo string, err error) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 {
		return "", fmt.Errorf("malformed key line: %q", line)
	}
	if !knownKeyAlgos[fields[0]] {
		return "", fmt.Errorf("unknown key algorithm %q", fields[0])
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return "", fmt.Errorf("bad base64: %w", err)
	}
	typ, _, err := readString(blob)
	if err != nil {
		return "", err
	}
	if string(typ) != fields[0] {
		return "", fmt.Errorf("key body type %q != declared %q", typ, fields[0])
	}
	return fields[0], nil
}

// parseAuthorizedKey parses a single "ssh-ed25519 <base64> [comment]" line.
// Only ed25519 keys are accepted as signers — they are all we pin and all the
// verifier knows how to check, which keeps the trust path to a single
// ed25519.Verify call.
func parseAuthorizedKey(line string) (*PinnedKey, error) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 {
		return nil, fmt.Errorf("malformed key line: %q", line)
	}
	algo := fields[0]
	if algo != "ssh-ed25519" {
		return nil, fmt.Errorf("unsupported signer algorithm %q (only ssh-ed25519)", algo)
	}
	wire, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return nil, fmt.Errorf("bad base64 in key line: %w", err)
	}
	typ, rest, err := readString(wire)
	if err != nil {
		return nil, err
	}
	if string(typ) != "ssh-ed25519" {
		return nil, fmt.Errorf("key body type %q != ssh-ed25519", typ)
	}
	pub, _, err := readString(rest)
	if err != nil {
		return nil, err
	}
	if len(pub) != 32 {
		return nil, fmt.Errorf("ed25519 key is %d bytes, want 32", len(pub))
	}
	comment := ""
	if len(fields) >= 3 {
		comment = fields[2]
	}
	sum := sha256.Sum256(wire)
	return &PinnedKey{
		Comment:     comment,
		Algo:        algo,
		Wire:        wire,
		Ed25519:     pub,
		Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]),
	}, nil
}
