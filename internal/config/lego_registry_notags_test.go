//go:build !lego_dns

package config

import (
	"strings"
	"testing"
)

// The default build must refuse `dns.provider: lego` with the rebuild instruction, from the config
// package alone.
func TestTheDefaultBuildRefusesTheLegoProvider(t *testing.T) {
	if acmeSupportsLegoProviders {
		t.Fatal("the default build must not claim lego's registry is available")
	}

	path := writeConfig(t, minimalWithDNS+`
dns:
  provider: lego
  legoProvider: cloudflare
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("dns.provider=lego must be refused at load time in a build without the registry")
	}
	if !strings.Contains(err.Error(), "lego_dns") {
		t.Errorf("the refusal must name the tag to rebuild with, got %v", err)
	}
}
