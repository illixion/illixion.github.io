package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// SSHSIG implements verification of OpenSSH signatures as produced by
// `ssh-keygen -Y sign`, per the PROTOCOL.sshsig specification. We implement it
// directly rather than shelling out to ssh-keygen because:
//   - Windows and OpenWRT/dropbear targets have no `ssh-keygen -Y verify`.
//   - It keeps verification a single in-process ed25519.Verify with no deps.
//
// Armored format (between the PEM-like markers, base64):
//
//	byte[6]  MAGIC      = "SSHSIG"
//	uint32   version    = 1
//	string   publickey  (SSH wire format)
//	string   namespace
//	string   reserved
//	string   hash_algo  ("sha256" | "sha512")
//	string   signature  (SSH signature blob)
//
// The signature is computed over this blob:
//
//	byte[6]  MAGIC = "SSHSIG"
//	string   namespace
//	string   reserved
//	string   hash_algo
//	string   H(message)
const (
	sshsigMagic     = "SSHSIG"
	sshsigNamespace = "file" // ssh-keygen -Y sign -n file
)

// VerifySSHSIG checks that `sig` (an armored SSHSIG) is a valid signature over
// `message` by one of the `pinned` keys, where that key is not in `disabled`
// (matched by fingerprint). It returns the signing key on success.
func VerifySSHSIG(message, sig []byte, pinned []*PinnedKey, disabled map[string]bool) (*PinnedKey, error) {
	blob, err := dearmor(sig)
	if err != nil {
		return nil, err
	}

	if len(blob) < 6 || string(blob[:6]) != sshsigMagic {
		return nil, fmt.Errorf("not an SSHSIG blob (bad magic)")
	}
	rest := blob[6:]
	if len(rest) < 4 {
		return nil, errShortWire
	}
	version := uint32(rest[0])<<24 | uint32(rest[1])<<16 | uint32(rest[2])<<8 | uint32(rest[3])
	if version != 1 {
		return nil, fmt.Errorf("unsupported SSHSIG version %d", version)
	}
	rest = rest[4:]

	pubWire, rest, err := readString(rest)
	if err != nil {
		return nil, err
	}
	namespace, rest, err := readString(rest)
	if err != nil {
		return nil, err
	}
	reserved, rest, err := readString(rest)
	if err != nil {
		return nil, err
	}
	hashAlgo, rest, err := readString(rest)
	if err != nil {
		return nil, err
	}
	sigBlob, _, err := readString(rest)
	if err != nil {
		return nil, err
	}

	if string(namespace) != sshsigNamespace {
		return nil, fmt.Errorf("signature namespace %q != %q", namespace, sshsigNamespace)
	}

	// Identify which pinned key produced this signature.
	signer := matchPinned(pubWire, pinned)
	if signer == nil {
		return nil, fmt.Errorf("signature is by an unpinned key; refusing")
	}
	if disabled[signer.Fingerprint] {
		return nil, fmt.Errorf("signer %s (%s) has been revoked; refusing", signer.Comment, signer.Fingerprint)
	}

	// Hash the message with the algorithm named in the signature.
	var msgHash []byte
	switch string(hashAlgo) {
	case "sha256":
		h := sha256.Sum256(message)
		msgHash = h[:]
	case "sha512":
		h := sha512.Sum512(message)
		msgHash = h[:]
	default:
		return nil, fmt.Errorf("unsupported hash algorithm %q", hashAlgo)
	}

	// Reconstruct the signed-data blob.
	var signed bytes.Buffer
	signed.WriteString(sshsigMagic)
	signed.Write(sshString(namespace))
	signed.Write(sshString(reserved))
	signed.Write(sshString(hashAlgo))
	signed.Write(sshString(msgHash))

	// Unwrap the inner SSH signature blob: string(sigtype) || string(rawsig).
	sigType, sr, err := readString(sigBlob)
	if err != nil {
		return nil, err
	}
	rawSig, _, err := readString(sr)
	if err != nil {
		return nil, err
	}
	if string(sigType) != "ssh-ed25519" {
		return nil, fmt.Errorf("unsupported signature type %q", sigType)
	}
	if len(rawSig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("ed25519 signature is %d bytes, want %d", len(rawSig), ed25519.SignatureSize)
	}

	if !ed25519.Verify(ed25519.PublicKey(signer.Ed25519), signed.Bytes(), rawSig) {
		return nil, fmt.Errorf("signature does not verify against %s", signer.Comment)
	}
	return signer, nil
}

// matchPinned returns the pinned key whose wire form equals pubWire, or nil.
func matchPinned(pubWire []byte, pinned []*PinnedKey) *PinnedKey {
	for _, k := range pinned {
		if bytes.Equal(k.Wire, pubWire) {
			return k
		}
	}
	return nil
}

// dearmor extracts the base64 payload from a "-----BEGIN SSH SIGNATURE-----"
// armored block. It also tolerates a raw (already base64-decoded) blob.
func dearmor(sig []byte) ([]byte, error) {
	if block, _ := pem.Decode(sig); block != nil {
		// ssh uses PEM-style armor with type "SSH SIGNATURE".
		return block.Bytes, nil
	}
	// Fallback: maybe it's bare base64.
	if decoded, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(sig))); err == nil {
		return decoded, nil
	}
	return nil, fmt.Errorf("could not parse SSH signature armor")
}
