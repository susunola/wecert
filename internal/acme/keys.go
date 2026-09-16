package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/susunola/wecert/internal/config"
)

// GenerateKey generates the certificate private key for the configured type.
// ECDSA P-256 is the default.
func GenerateKey(keyType string) (crypto.Signer, error) {
	switch keyType {
	case config.KeyTypeECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case config.KeyTypeECDSAP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case config.KeyTypeRSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case config.KeyTypeRSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	default:
		return nil, fmt.Errorf("unsupported key type %q", keyType)
	}
}

// MarshalPrivateKeyPEM always writes PKCS#8, so EC and RSA need no separate paths.
func MarshalPrivateKeyPEM(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParsePrivateKeyPEM parses all three private key encodings: PKCS#8, PKCS#1, SEC1.
func ParsePrivateKeyPEM(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found in private key")
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key of type %T is not a crypto.Signer", key)
		}
		return signer, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("unrecognized private key encoding (tried PKCS#8, PKCS#1, SEC1)")
}

// CreateCSRDER builds a certificate signing request and returns it DER-encoded.
//
// Why DER and not PEM: lego's api.OrderService.UpdateForCSR base64url-encodes the
// bytes it is handed and puts *that* into the ACME csr field. Hand it PEM and the
// CA receives base64url(PEM text); decoding that and parsing it as DER fails with
// "asn1: structure error: tags don't match ... certificateRequest".
//
// An empty Subject is deliberate: the classic profile promotes the first dNSName
// to CN, the tlsserver profile carries no CN at all. Let the CA decide that.
func CreateCSRDER(key crypto.Signer, domains []string) ([]byte, error) {
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{},
		DNSNames: domains,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}
	return der, nil
}

// ParseLeaf parses the first certificate (the leaf) out of a fullchain.
func ParseLeaf(fullchainPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(fullchainPEM)
	if block == nil {
		return nil, errors.New("no PEM block found in certificate")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected CERTIFICATE block, got %q", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

// CoverageDrift compares the domain set the config expects against the SANs the
// certificate actually carries.
//
// It returns whether they differ, plus a readable description of the drift.
//
// This is the key step of declarative convergence: VerifyCoverage only answers
// "is this new certificate good enough", and gates a deploy; CoverageDrift answers
// "does the certificate in effect still match the config", and feeds every round's
// decision. Without the latter, adding a domain to the config looks like nothing to
// do, and the new domain waits for the next renewal window -- under the classic
// profile that can be a whole validity period away.
func CoverageDrift(leaf *x509.Certificate, want []string) (bool, string) {
	if leaf == nil {
		return false, ""
	}
	if config.DomainKey(leaf.DNSNames) == config.DomainKey(want) {
		return false, ""
	}

	missing, extra := config.DiffDomains(want, leaf.DNSNames)
	var parts []string
	if len(missing) > 0 {
		parts = append(parts, "required by the config but missing: "+strings.Join(missing, ","))
	}
	if len(extra) > 0 {
		parts = append(parts, "certificate present but removed from the config: "+strings.Join(extra, ","))
	}
	return true, strings.Join(parts, "; ")
}

// VerifyCoverage confirms the certificate that came back really covers every
// domain we asked for.
//
// This is the last gate before deploying: without it an incomplete order result
// would be pushed straight to the CLB and take production down.
func VerifyCoverage(leaf *x509.Certificate, want []string) error {
	have := make(map[string]bool, len(leaf.DNSNames))
	for _, n := range leaf.DNSNames {
		have[strings.ToLower(n)] = true
	}
	var missing []string
	for _, n := range want {
		if !have[strings.ToLower(n)] {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("the issued certificate does not cover these domains: %v (it contains %v)", missing, leaf.DNSNames)
	}
	return nil
}
