//go:build lego_dns

package config

import "testing"

// A binary built with the registry must accept `dns.provider: lego`, from the config package alone.
//
// This test exists because the flag used to be set by internal/acme's init, which made it a
// property of the packages a binary links rather than of how it was built. cmd/wecert-onboard reads
// a config without linking internal/acme, so a lego_dns build of it refused a valid configuration.
// Nothing here links acme: the answer must come from this package's own build tag.
func TestTheLegoProviderFlagComesFromTheBuildTagNotTheLinker(t *testing.T) {
	if !acmeSupportsLegoProviders {
		t.Fatal("this binary was built with -tags lego_dns, so config validation must accept " +
			"dns.provider=lego -- including in a binary that does not link internal/acme")
	}

	path := writeConfig(t, minimalWithDNS+`
dns:
  provider: lego
  legoProvider: cloudflare
`)
	if _, err := Load(path); err != nil {
		t.Fatalf("a registry build must load a valid lego config: %v", err)
	}
}
