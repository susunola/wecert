package redact

import (
	"strings"
	"testing"
)

// LastError is written through Secrets and then served verbatim to a read-only
// token by /hook/status and /api/inventory. A provider error that embeds a
// credential must not survive that trip.
func TestSecretsCoversWhatLastErrorCarries(t *testing.T) {
	cases := []struct {
		in   string
		leak []string
	}{
		{"dns-01: Bearer AbcDef1234567890 timed out", []string{"AbcDef1234567890"}},
		{"aws: AccessKeyId=AKIA0123456789ABCDEF denied", []string{"AKIA0123456789ABCDEF"}},
		{"config token=supersecret99 invalid", []string{"supersecret99"}},
		{"pem -----BEGIN PRIVATE KEY-----\nMII...\n-----END PRIVATE KEY-----", []string{"MII..."}},
	}
	for _, tc := range cases {
		got := Secrets(tc.in)
		for _, leak := range tc.leak {
			if strings.Contains(got, leak) {
				t.Errorf("Secrets(%q) leaked %q: %q", tc.in, leak, got)
			}
		}
	}
}
