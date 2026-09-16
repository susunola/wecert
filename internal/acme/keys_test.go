package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// leafFor signs a leaf that really belongs to key.
func leafFor(t *testing.T, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		DNSNames:              []string{"example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("issue leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func TestVerifyKeyMatchAcceptsTheOrderKey(t *testing.T) {
	key := newKey(t)
	keyPEM, err := MarshalPrivateKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyKeyMatch(leafFor(t, key), keyPEM); err != nil {
		t.Errorf("the leaf belongs to this key: %v", err)
	}
}

// The whole point: a leaf that covers the right names and lives long enough, but belongs to
// another key, would be deployed over a working certificate and break every handshake.
func TestVerifyKeyMatchRejectsADifferentKey(t *testing.T) {
	leaf := leafFor(t, newKey(t))
	keyPEM, err := MarshalPrivateKeyPEM(newKey(t))
	if err != nil {
		t.Fatal(err)
	}

	err = VerifyKeyMatch(leaf, keyPEM)
	if err == nil {
		t.Fatal("a leaf for a different key must be rejected")
	}
	if !strings.Contains(err.Error(), "does not belong to the private key") {
		t.Errorf("the error must name the actual fault, got: %v", err)
	}
}

// Same curve, different key: the comparison must be on the key material, not on the
// algorithm, or every P-256 certificate would look like a match.
func TestVerifyKeyMatchComparesKeyMaterial(t *testing.T) {
	leaf := leafFor(t, newKey(t))
	other := newKey(t)
	if leaf.PublicKey.(*ecdsa.PublicKey).Equal(&other.PublicKey) {
		t.Fatal("the test's two keys must differ")
	}
	keyPEM, err := MarshalPrivateKeyPEM(other)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyKeyMatch(leaf, keyPEM); err == nil {
		t.Error("two different P-256 keys must not compare equal")
	}
}

// An unreadable key is a hard failure, not a pass: silently skipping the check would make it
// decorative exactly when something is already wrong.
func TestVerifyKeyMatchRejectsAnUnparseableKey(t *testing.T) {
	leaf := leafFor(t, newKey(t))

	for name, keyPEM := range map[string][]byte{
		"garbage": []byte("not a pem block at all"),
		"empty":   nil,
		"wrong type": pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Bytes: []byte{0x01, 0x02, 0x03},
		}),
	} {
		if err := VerifyKeyMatch(leaf, keyPEM); err == nil {
			t.Errorf("%s: an unparseable key must fail the check", name)
		}
	}
}
