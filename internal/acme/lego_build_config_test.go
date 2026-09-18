package acme

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/susunola/wecert/internal/config"
)

// The build tag has to reach config validation. This is the half of the contract an operator
// actually meets, and it is the half no test covered before: `config` cannot import `acme`
// (that would be a cycle), so the config package's own test can only observe its own zero value
// -- which happens to be the right answer in the default build and is why a test living there
// passed while proving nothing, and went on passing in a `-tags lego_dns` binary that would have
// wrongly rejected a valid config.
//
// The test lives here, in the acme package, because that is where the wiring is: this test binary
// runs acme's init by construction. The expectation comes from the build-tag pair, so the two
// directions cannot be satisfied by the same accident.
func TestLegoProviderSupportMatchesTheBuildTag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := `
statePath: /tmp/wecert-test.db
acme:
  directory: https://acme-staging-v02.api.letsencrypt.org/directory
  email: ops@atomwangnus.com
tencent:
  credentialMode: static
  secretId: id
  secretKey: key
  regions: [ap-guangzhou]
certificates:
  - name: example-com
    domains: ["example.com"]
dns:
  provider: lego
  legoProvider: cloudflare
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := config.Load(path)

	if legoProviderAvailable {
		if err != nil {
			t.Fatalf("this binary was built with -tags lego_dns, so dns.provider=lego is a valid "+
				"configuration, but loading it failed: %v\n"+
				"If the message tells the operator to rebuild with -tags lego_dns, then acme's init "+
				"did not reach config validation and the tag is only half wired.", err)
		}
		return
	}

	if err == nil {
		t.Fatal("this binary was built without -tags lego_dns, so dns.provider=lego must be " +
			"refused at load time rather than accepted and failing once the ACME account is touched")
	}
	if !strings.Contains(err.Error(), "-tags lego_dns") {
		t.Errorf("the refusal must name the build tag that enables the provider, got %q", err)
	}
}
