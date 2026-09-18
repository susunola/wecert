package acme

// leafDER extracts the first certificate's DER bytes from a PEM bundle.
//
// Test-only helper (revoke_test.go): production code goes through leafCertificate
// directly, which is why this lives here rather than in revoke.go.
func leafDER(certPEM []byte) ([]byte, error) {
	leaf, err := leafCertificate(certPEM)
	if err != nil {
		return nil, err
	}
	return leaf.Raw, nil
}
