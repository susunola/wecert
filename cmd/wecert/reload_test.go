package main

import (
	"strings"
	"testing"

	"github.com/susunola/wecert/internal/config"
)

func TestReloadImmutableRejectsResourceIdentityChanges(t *testing.T) {
	base := &config.Config{}
	base.StatePath = "/var/lib/wecert/state.db"
	base.ACME.Directory = "https://acme.example/directory"
	base.Metrics.Listen = "127.0.0.1:9800"
	base.Webhook.Listen = "127.0.0.1:9801"

	cases := []struct {
		name string
		edit func(*config.Config)
		want string
	}{
		{"state", func(c *config.Config) { c.StatePath = "/other/state.db" }, "statePath"},
		{"directory", func(c *config.Config) { c.ACME.Directory = "https://other/directory" }, "acme.directory"},
		{"metrics", func(c *config.Config) { c.Metrics.Listen = "127.0.0.1:9900" }, "metrics.listen"},
		{"webhook", func(c *config.Config) { c.Webhook.Listen = "127.0.0.1:9901" }, "webhook.listen"},
		{"stateEncryption", func(c *config.Config) { c.StateEncryption.KeyFile = "/other/master.key" }, "stateEncryption"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			next := *base
			tc.edit(&next)
			err := reloadImmutable(base, &next)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("reloadImmutable() = %v, want error mentioning %q", err, tc.want)
			}
		})
	}
	if err := reloadImmutable(base, base); err != nil {
		t.Fatalf("identical config should reload: %v", err)
	}
}
