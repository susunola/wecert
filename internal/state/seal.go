package state

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

// sealedPrefix makes encrypted blobs self-identifying, so a migration can reject
// a wrong master key instead of treating ciphertext as PEM.
var sealedPrefix = []byte("wecert-seal-v1\x00")

type sealer struct{ aead cipher.AEAD }

// newSealer accepts arbitrary secret material from a credential file and derives
// a fixed AES-256 key. Callers must keep that material out of logs and YAML.
func newSealer(master []byte) (*sealer, error) {
	if len(master) == 0 {
		return nil, errors.New("state encryption master key is empty")
	}
	sum := sha256.Sum256(master)
	b, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	return &sealer{aead: a}, nil
}

func (s *sealer) seal(plain, aad []byte) ([]byte, error) {
	if len(plain) == 0 {
		return plain, nil
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := append(append([]byte{}, sealedPrefix...), nonce...)
	return s.aead.Seal(out, nonce, plain, aad), nil
}

func (s *sealer) open(blob, aad []byte) ([]byte, error) {
	if len(blob) == 0 {
		return blob, nil
	}
	if len(blob) < len(sealedPrefix)+s.aead.NonceSize() || string(blob[:len(sealedPrefix)]) != string(sealedPrefix) {
		return nil, errors.New("state key material is not encrypted with this format")
	}
	nonce := blob[len(sealedPrefix) : len(sealedPrefix)+s.aead.NonceSize()]
	plain, err := s.aead.Open(nil, nonce, blob[len(sealedPrefix)+s.aead.NonceSize():], aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt state key material: %w", err)
	}
	return plain, nil
}
