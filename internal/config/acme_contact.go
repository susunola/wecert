package config

import ()

// reservedContactDomains and reservedContactTLDs are the names a CA refuses as a contact address.
//
// Let's Encrypt answers 400 invalidContact ("contact email has forbidden domain") for these, and it
// does so at ACCOUNT REGISTRATION -- before a single certificate is issued. The shipped example config
// used ops@example.com, so the documented quick start failed at the documented `-dry-run` step with a
// CA-side error that names neither the file nor the line, and the operator had to work out that the
// address in the example was the problem. Catching it here turns that into a local, specific error.
//
// The lists are the documented reserved names (RFC 2606 / RFC 6761): the "example" domains and the
// special-use TLDs. Nothing else is guessed at -- a typo in a real domain is not this check's
// business, and the CA will refuse what it refuses.
var reservedContactDomains = map[string]bool{
	"example.com": true,
	"example.net": true,
	"example.org": true,
	"example.edu": true,
}

var reservedContactTLDs = map[string]bool{
	"example":   true,
	"invalid":   true,
	"test":      true,
	"localhost": true,
}

// validateContactEmail refuses an address a CA will not accept, before it reaches the CA.
type ACME struct {
	Directory string `yaml:"directory"`
	// FallbackDirectories are used only when the primary ACME directory is
	// unavailable at transport level (or explicitly rejects new orders for the
	// account). They are not a retry for DNS or authorization failures.
	FallbackDirectories []string `yaml:"fallbackDirectories,omitempty"`
	Email               string   `yaml:"email"`
	// EAB supplies the External Account Binding credentials required by some
	// commercial and private ACME directories. HMACFile keeps the binding secret
	// out of config.yaml and works with systemd LoadCredential.
	EAB ACMEExternalAccountBinding `yaml:"eab,omitempty"`
}

type ACMEExternalAccountBinding struct {
	KID      string `yaml:"kid,omitempty"`
	HMAC     string `yaml:"hmac,omitempty"`
	HMACFile string `yaml:"hmacFile,omitempty"`
}
