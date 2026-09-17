//go:build lego_dns

package acme

import (
	"context"

	"github.com/go-acme/lego/v4/challenge"
	legodns "github.com/go-acme/lego/v4/providers/dns"
)

// legoProviderAvailable tells the build-tag tests which half of the pair this is. It is not read
// by the program: config validation is what accepts `dns.provider: lego` here, and it learns that
// from internal/config's own build-tagged file (not from this package's init -- see there for why).
const legoProviderAvailable = true

// newLegoProvider builds any of lego's ~198 DNS providers by name. Its counterpart under
// `!lego_dns` returns the rebuild instruction instead; the two are asserted together by
// lego_build_tags_test.go and lego_build_default_test.go.
//
// Each provider reads its own credentials from the environment using lego's documented
// variables (CLOUDFLARE_DNS_API_TOKEN, AWS_ACCESS_KEY_ID, ...), which is why this needs no
// per-provider configuration: a generic credential map would have to mirror 198 different
// schemas, and lego already defines them.
func newLegoProvider(name string) func(context.Context) (challenge.Provider, error) {
	return func(context.Context) (challenge.Provider, error) {
		// Built per call on purpose, like the Tencent provider: constructing a provider only
		// creates an SDK client, and a long-running process must not hold credentials it
		// fetched hours ago.
		return legodns.NewDNSChallengeProviderByName(name)
	}
}
