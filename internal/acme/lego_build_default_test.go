//go:build !lego_dns

package acme

import (
	"context"
	"strings"
	"testing"
)

// The default build must refuse to construct a lego provider, and say how to get one.
//
// This is the backstop half of a two-part contract; the operator-facing half is that
// `config.Load` refuses the same config earlier, and is asserted in
// internal/config/lego_build_tag_default_test.go. Both are needed: the config check is what a
// person actually sees, and this one is what stops a config that never went through validation
// from reaching the network with a nil provider.
func TestLegoProviderIsRefusedInTheDefaultBuild(t *testing.T) {
	build := newLegoProvider("cloudflare")
	if build == nil {
		t.Fatal("newLegoProvider must always return a constructor, so the caller does not have to " +
			"nil-check a build-tag branch")
	}

	p, err := build(context.Background())
	if err == nil {
		t.Fatalf("the default build must not construct a lego provider; got %T with no error", p)
	}
	if p != nil {
		t.Errorf("a refused provider must not also be returned, got %T", p)
	}
	for _, want := range []string{"-tags lego_dns", "cloudflare"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error must mention %q so the operator can act on it, got %q", want, err)
		}
	}
}
