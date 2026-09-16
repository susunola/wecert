//go:build !lego_dns

package acme

import (
	"context"
	"fmt"

	"github.com/go-acme/lego/v4/challenge"

	"github.com/susunola/wecert/internal/config"
)

func init() { config.SetLegoProviderSupport(false) }

// legoProviderAvailable tells the build-tag tests which half of the pair this is. It is not read
// by the program: config validation is what refuses `dns.provider: lego` here, and it learns that
// from the init above rather than from this constant.
const legoProviderAvailable = false

// newLegoProvider exists so the two build variants have identical signatures, and as the backstop
// for a config that reaches the solver without having been validated. `config.Load` is what
// normally refuses `dns.provider: lego` in this build, and it refuses it with the same
// instruction, before the ACME account has been touched -- see lego_build_default_test.go, which
// asserts both halves of that.
//
// Why this is a build tag rather than always-available. lego's registry imports all ~198
// provider packages, and between them they depend on hundreds of third-party modules (the
// Azure and AWS SDKs, the Huawei, Yandex, Oracle and Akamai SDKs, and so on). Compiling them in
// takes the binary from ~18 MB to far more and, more importantly, makes all of that code part
// of the supply chain of a program whose job is holding private keys. The default build
// therefore keeps its two native providers -- DNSPod and Tencent Cloud DNS, which is what the
// deployment this exists for uses -- and the rest are one flag away for anyone who needs them.
func newLegoProvider(name string) func(context.Context) (challenge.Provider, error) {
	return func(context.Context) (challenge.Provider, error) {
		return nil, fmt.Errorf(
			"dns.provider \"lego\" needs a build that includes lego's provider registry, which this "+
				"binary is not: rebuild with -tags lego_dns to get all ~198 lego DNS providers "+
				"(requested: %q). The default build carries only the native dnspod and tencentcloud "+
				"providers because the registry pulls in hundreds of third-party SDKs", name)
	}
}
