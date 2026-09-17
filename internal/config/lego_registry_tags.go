//go:build lego_dns

package config

// The lego provider registry is compiled in, so `dns.provider: lego` is a valid configuration.
//
// This lives in the config package rather than in internal/acme on purpose. The flag used to be
// set by acme's init, which made it a property of WHICH PACKAGES A BINARY LINKS rather than of how
// it was built: cmd/wecert-onboard reads the config but does not link internal/acme, so a
// lego_dns build of it refused a perfectly valid `dns.provider: lego` configuration and told the
// operator to rebuild with the tag they had just used. A build-tagged file here is compiled into
// every binary that can read a config, so the answer cannot depend on the linker.
func init() { acmeSupportsLegoProviders = true }
