package config

import (
	"strings"
	"testing"
)

// A negative TTL is a typo, not "unset" -- the same rule failureFallback.* already
// applies. It used to be silently replaced by the 600 default, throwing away the
// number the operator wrote.
func TestDNSNegativeTTLIsRejectedNotDefaulted(t *testing.T) {
	body := strings.Replace(minimalPrefix, "  loginToken: token\n", "  loginToken: token\n  ttl: -1\n", 1) + `certificates:
  - name: example-com
    domains: ["example.com"]
`
	_, err := Load(writeConfig(t, body))
	if err == nil {
		t.Fatal("a negative dns.ttl must be rejected rather than silently defaulted")
	}
	if !strings.Contains(err.Error(), "dns.ttl") {
		t.Errorf("the error must name the field, got %v", err)
	}
}

// The default and an explicit value must both still load, or the negative check
// would break every existing config.
func TestDNSTTLDefaultAndExplicitStillLoad(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalPrefix+`certificates:
  - name: example-com
    domains: ["example.com"]
`))
	if err != nil {
		t.Fatalf("the default must load: %v", err)
	}
	if cfg.DNS.TTL != 600 {
		t.Errorf("unset ttl must default to 600 (the DNSPod free-tier floor), got %d", cfg.DNS.TTL)
	}

	body := strings.Replace(minimalPrefix, "  loginToken: token\n", "  loginToken: token\n  ttl: 60\n", 1) + `certificates:
  - name: example-com
    domains: ["example.com"]
`
	cfg, err = Load(writeConfig(t, body))
	if err != nil {
		t.Fatalf("an explicit ttl must load: %v", err)
	}
	if cfg.DNS.TTL != 60 {
		t.Errorf("an explicit ttl must be kept, got %d", cfg.DNS.TTL)
	}
}

// legoProvider is read only when provider is "lego". Next to a native provider it
// means the operator believes challenges go through, say, Cloudflare while they
// actually go through dnspod -- rejected loudly rather than silently ignored, the
// same call desiredState.path under mode=static already makes.
func TestLegoProviderWithoutTheLegoProviderIsRejected(t *testing.T) {
	for _, provider := range []string{"dnspod", "tencentcloud"} {
		body := minimalWithDNS + `dns:
  provider: ` + provider + `
  loginToken: token
  legoProvider: cloudflare
`
		_, err := Load(writeConfig(t, body))
		if err == nil {
			t.Errorf("provider=%s with legoProvider set must be rejected: the field would be silently ignored", provider)
			continue
		}
		if !strings.Contains(err.Error(), "legoProvider") {
			t.Errorf("provider=%s: the error must name the field that would be ignored, got %v", provider, err)
		}
	}
}
