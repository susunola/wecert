//go:build lego_dns

package acme

import (
	"context"
	"strings"
	"testing"
)

// With the tag, the lego branch must actually be the one that runs.
//
// The assertion is deliberately about *which* failure comes back rather than success: a real
// provider is constructed from the environment (CLOUDFLARE_DNS_API_TOKEN and friends), so a test
// asserting success would need credentials and would be testing lego's configuration parsing
// rather than this build tag. Asking for a provider name that cannot exist gives an error either
// way -- and the two branches produce distinguishable ones. The rebuild instruction can only come
// from the other side of the tag, so its absence is what proves the tag took effect.
func TestLegoProviderIsWiredWhenTheTagIsSet(t *testing.T) {
	p, err := newLegoProvider("wecert-definitely-not-a-real-provider")(context.Background())
	if p != nil {
		t.Errorf("a provider that cannot exist must not be constructed, got %T", p)
	}
	if err == nil {
		t.Fatal("an unknown provider name must be an error, not a silent nil")
	}
	if strings.Contains(err.Error(), "-tags lego_dns") {
		t.Errorf("this binary was built with -tags lego_dns, but the provider registry branch did "+
			"not run: got the rebuild instruction instead (%q), which means lego_dns is not "+
			"actually wired into newLegoProvider", err)
	}
}
