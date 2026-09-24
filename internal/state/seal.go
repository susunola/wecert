package state

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// Blob prefixes identify which KDF produced the AEAD key. A single prefix cannot
// serve two KDFs: switching derivation without a new marker silently locks every
// existing sealed row (the comment that claimed "v1 still decrypts" was false).
var (
	sealedPrefixV1 = []byte("wecert-seal-v1\x00") // SHA-256(master) -> AES-256-GCM
	sealedPrefixV2 = []byte("wecert-seal-v2\x00") // Argon2id(master) -> AES-256-GCM
	// sealedPrefix is the version new writes emit.
	sealedPrefix = sealedPrefixV2
)

type sealer struct {
	// v2 is what seal() uses.
	v2 cipher.AEAD
	// v1 is only for opening blobs written before the KDF upgrade. nil when the
	// caller never needs to read legacy material (unit tests).
	v1 cipher.AEAD
}

// newSealer derives both keys from the same master. Callers must keep that material
// out of logs and YAML.
func newSealer(master []byte) (*sealer, error) {
	if len(master) == 0 {
		return nil, errors.New("state encryption master key is empty")
	}
	// Argon2id, not a bare hash: a password-shaped master key must not be cheap to
	// brute-force offline from a stolen state.db. Salt is the fixed application
	// context -- the input is already a high-entropy key file in the intended
	// deployment, and a per-open random salt would make every blob undecryptable
	// after a restart.
	sum := argon2.IDKey(master, []byte("wecert-seal-v2"), 1, 64*1024, 4, 32)
	a2, err := aes.NewCipher(sum)
	if err != nil {
		return nil, err
	}
	gcm2, err := cipher.NewGCM(a2)
	if err != nil {
		return nil, err
	}
	// v1: SHA-256(master). Kept only to read pre-upgrade blobs; migrateSealedMaterial
	// re-seals them to v2 so this path shrinks toward empty.
	v1sum := sha256.Sum256(master)
	a1, err := aes.NewCipher(v1sum[:])
	if err != nil {
		return nil, err
	}
	gcm1, err := cipher.NewGCM(a1)
	if err != nil {
		return nil, err
	}
	return &sealer{v2: gcm2, v1: gcm1}, nil
}

func (s *sealer) seal(plain, aad []byte) ([]byte, error) {
	if len(plain) == 0 {
		return plain, nil
	}
	nonce := make([]byte, s.v2.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := append(append([]byte{}, sealedPrefixV2...), nonce...)
	return s.v2.Seal(out, nonce, plain, aad), nil
}

func (s *sealer) open(blob, aad []byte) ([]byte, error) {
	if len(blob) == 0 {
		return blob, nil
	}
	switch {
	case bytes.HasPrefix(blob, sealedPrefixV2):
		return s.openWith(s.v2, sealedPrefixV2, blob, aad)
	case bytes.HasPrefix(blob, sealedPrefixV1):
		return s.openWith(s.v1, sealedPrefixV1, blob, aad)
	default:
		return nil, errors.New("state key material is not encrypted with this format")
	}
}

func (s *sealer) openWith(aead cipher.AEAD, prefix, blob, aad []byte) ([]byte, error) {
	if len(blob) < len(prefix)+aead.NonceSize() {
		return nil, errors.New("state key material is truncated")
	}
	nonce := blob[len(prefix) : len(prefix)+aead.NonceSize()]
	plain, err := aead.Open(nil, nonce, blob[len(prefix)+aead.NonceSize():], aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt state key material: %w", err)
	}
	return plain, nil
}

// isSealed reports whether a blob is already sealed (any version).
func isSealed(blob []byte) bool {
	return bytes.HasPrefix(blob, sealedPrefixV1) || bytes.HasPrefix(blob, sealedPrefixV2)
}

// isSealedV1 reports whether a blob still uses the pre-upgrade KDF.
func isSealedV1(blob []byte) bool {
	return bytes.HasPrefix(blob, sealedPrefixV1)
}
