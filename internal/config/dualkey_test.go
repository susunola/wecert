package config

import (
	"strings"
	"testing"
)

// The same identifier set with DIFFERENT key algorithms is a legitimate
// dual-certificate setup (an RSA certificate beside an ECDSA one, so clients
// without ECDSA still get served): those are distinct certificates with distinct
// keys, not duplicates. The dedupe check used to key on the domain set alone and
// rejected this.
func TestSameDomainSetWithDifferentKeyTypesIsAllowed(t *testing.T) {
	certs := []Certificate{
		{Name: "example-com", Domains: []string{"example.com"}, KeyType: KeyTypeECDSAP256},
		{Name: "example-com-rsa", Domains: []string{"example.com"}, KeyType: KeyTypeRSA2048},
	}
	if err := NormalizeCertificates(certs); err != nil {
		t.Fatalf("an RSA+ECDSA pair over the same names must be allowed, got %v", err)
	}
}

// Same set AND same key type is still a duplicate: both would share the
// 5-per-exact-set/7-days quota and cover the same names with the same algorithm.
func TestSameDomainSetWithTheSameKeyTypeIsStillRejected(t *testing.T) {
	certs := []Certificate{
		{Name: "example-com", Domains: []string{"example.com"}, KeyType: KeyTypeECDSAP256},
		{Name: "example-com-copy", Domains: []string{"example.com"}, KeyType: KeyTypeECDSAP384},
	}
	if err := NormalizeCertificates(certs); err != nil {
		t.Fatalf("a different algorithm is a different certificate, got %v", err)
	}

	certs[1].KeyType = KeyTypeECDSAP256
	err := NormalizeCertificates(certs)
	if err == nil {
		t.Fatal("the same identifier set with the same keyType must still be rejected")
	}
	if !strings.Contains(err.Error(), "same identifier set") {
		t.Errorf("the error should say why, got %v", err)
	}
}
