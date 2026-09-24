package backup

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// SignSnapshot returns the hex HMAC-SHA256 of the snapshot bytes.
//
// Why this exists: a writable backup bucket is not a trusted restore source. Anyone
// who can PutObject under the snapshot prefix can plant a state.db that replaces
// the live one (including every private key) on the next restore. The HMAC is the
// "we wrote this" proof; Verify refuses a remote object that does not carry it.
// The key is separate from the state-encryption master -- leaking one must not
// unlock the other.
func SignSnapshot(key, data []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySnapshot checks data against a previously computed hex MAC.
func VerifySnapshot(key, data []byte, wantHex string) error {
	want, err := hex.DecodeString(strings.TrimSpace(wantHex))
	if err != nil {
		return fmt.Errorf("snapshot signature is not hex: %w", err)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	if !hmac.Equal(mac.Sum(nil), want) {
		return fmt.Errorf("snapshot signature does not match: the object was not written by this deployment (or was altered)")
	}
	return nil
}

// WriteSnapshotSignature writes src+".hmac" beside the snapshot (local) or as the
// remote sidecar name. 0600: the signature is not secret, but the habit is the same.
func WriteSnapshotSignature(path, sig string) error {
	return os.WriteFile(path+".hmac", []byte(sig+"\n"), 0o600)
}

// ReadSnapshotSignature reads path+".hmac".
func ReadSnapshotSignature(path string) (string, error) {
	b, err := os.ReadFile(path + ".hmac")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// LoadHMACKey reads a signing key file. An empty path means "do not sign" -- and
// then remote restore is trusting the bucket, which is a deliberate choice only
// when no key is configured. A configured but unreadable key is an error, never
// a silent fall back to unsigned: that would leave the sidecar story intact in
// the operator's head while the objects on the remote were unsigned.
func LoadHMACKey(file string) ([]byte, error) {
	if file == "" {
		return nil, nil
	}
	b, err := os.ReadFile(os.ExpandEnv(file))
	if err != nil {
		return nil, fmt.Errorf("read backup HMAC key: %w", err)
	}
	key := []byte(strings.TrimSpace(string(b)))
	if len(key) == 0 {
		return nil, fmt.Errorf("backup HMAC key file %s is empty", file)
	}
	return key, nil
}
