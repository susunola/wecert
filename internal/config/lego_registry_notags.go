//go:build !lego_dns

package config

// The default build carries only the native providers (dnspod, tencentcloud, cloudflare and
// route53), and acmeSupportsLegoProviders already defaults to false. This file exists so the pair
// is explicit next to lego_registry_tags.go -- see there for why the answer must not depend on
// which packages a binary happens to link.
