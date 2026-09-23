package acme

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/susunola/wecert/internal/config"
)

// fakeCloudflareToken and fakeStaticAWSKeys are placeholders, never credentials: nothing here may
// reach the network, and no test below asks a provider to Present a record.
const (
	fakeCloudflareToken = "fake-cloudflare-scoped-token"
	fakeAWSAccessKeyID  = "AKIAIOSFODNN7EXAMPLE"
	fakeAWSSecretKey    = "fake-aws-secret-access-key"
)

// clearProviderEnv removes the ambient variables that would otherwise decide what these tests
// build -- the Cloudflare token fallbacks and the AWS region -- and keeps the AWS SDK out of a
// developer's shared profile, which is what makes a construction test hermetic rather than
// dependent on the machine running it.
func clearProviderEnv(t *testing.T) {
	t.Helper()
	for _, env := range []string{
		config.EnvCloudflareAPIToken, config.EnvCloudflareAPITokenAlt,
		config.EnvAWSRegion, config.EnvAWSDefaultRegion, "AWS_PROFILE",
	} {
		t.Setenv(env, "")
	}
}

// writeSolverConfig writes a complete config, with the given dns block, and loads it.
func writeSolverConfig(t *testing.T, dnsBlock string) *config.Config {
	t.Helper()
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
` + dnsBlock
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("the config must load: %v", err)
	}
	return cfg
}

// assertNotARebuildHint fails when the error carries lego's rebuild instruction.
//
// That instruction is the bug these two providers exist to fix: until they were native, the only
// way to reach Cloudflare or Route 53 was `dns.provider: lego`, and a default binary answered a
// perfectly valid config with "rebuild with -tags lego_dns" -- which pulls in all ~198 providers
// and their hundreds of SDKs. A regression that sends either provider back down the build-tagged
// branch would still produce *an* error, so the absence of that sentence is what has to be pinned.
func assertNotARebuildHint(t *testing.T, provider string, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if strings.Contains(err.Error(), "-tags lego_dns") {
		t.Fatalf("dns.provider=%s is native to every build, but building the solver answered with "+
			"lego's rebuild instruction instead: %v\n"+
			"This is the exact failure the native provider was added to remove: the case fell "+
			"through to the build-tagged lego branch, so an operator with a valid config is told "+
			"to compile ~198 providers into the binary.", provider, err)
	}
	t.Fatalf("dns.provider=%s must build from a valid config, got: %v", provider, err)
}

// Cloudflare is a first-class provider in the default build: config in, working solver out.
//
// The test deliberately goes through config.Load rather than a hand-built struct, because the
// interesting failure is a wiring gap between the two -- the YAML surface (dns.cloudflare.apiToken),
// the validation that accepts it, and the case in NewDNSSolver that consumes it. It must not be
// mistaken for the lego path, which an untagged binary refuses.
func TestCloudflareProviderIsNativeAndBuildsWithoutTheLegoRegistry(t *testing.T) {
	clearProviderEnv(t)

	cfg := writeSolverConfig(t, `  provider: cloudflare
  cloudflare:
    apiToken: `+fakeCloudflareToken+`
`)
	solver, err := NewDNSSolver(cfg.DNS, cfg.Tencent, slog.New(slog.NewTextHandler(io.Discard, nil)))
	assertNotARebuildHint(t, config.DNSProviderCloudflare, err)
	if solver == nil {
		t.Fatal("a valid cloudflare config must produce a solver")
	}
	if solver.PropagationTimeout() != cfg.DNS.Propagation {
		t.Errorf("PropagationTimeout() = %s, want the configured %s",
			solver.PropagationTimeout(), cfg.DNS.Propagation)
	}
}

// Route 53 is native too, and the static-key shape must build without touching the network.
func TestRoute53ProviderIsNativeAndBuildsWithoutTheLegoRegistry(t *testing.T) {
	clearProviderEnv(t)

	cfg := writeSolverConfig(t, `  provider: route53
  route53:
    region: us-east-1
    accessKeyId: `+fakeAWSAccessKeyID+`
    secretAccessKey: `+fakeAWSSecretKey+`
`)
	solver, err := NewDNSSolver(cfg.DNS, cfg.Tencent, slog.New(slog.NewTextHandler(io.Discard, nil)))
	assertNotARebuildHint(t, config.DNSProviderRoute53, err)
	if solver == nil {
		t.Fatal("a valid route53 config must produce a solver")
	}

	// The chain shape -- region only, credentials left to the SDK -- must build as well: that is
	// the instance-role deployment, and it is the one a required key pair would have broken.
	clearProviderEnv(t)
	cfg = writeSolverConfig(t, `  provider: route53
  route53:
    region: us-east-1
`)
	solver, err = NewDNSSolver(cfg.DNS, cfg.Tencent, slog.New(slog.NewTextHandler(io.Discard, nil)))
	assertNotARebuildHint(t, config.DNSProviderRoute53, err)
	if solver == nil {
		t.Fatal("a route53 config with no static keys must build: the AWS default chain, including " +
			"an instance role, is a valid credential source")
	}
}

// The two config builders must carry what the caller passed, and keep their API calls bounded.
//
// A struct literal does not inherit lego's defaults, which is a hazard this package already
// documents for tencentcloud/dnspod; these two start from NewDefaultConfig precisely so that
// MaxRetries, WaitForRecordSetsChanged and the AWS_HOSTED_ZONE_ID fallback survive. The assertions
// below pin both halves: our fields are written over the defaults, and the defaults we rely on are
// still lego's.
func TestCloudflareAndRoute53ConfigsKeepTheirSettings(t *testing.T) {
	dnsCfg := config.DNS{
		TTL:         600,
		Propagation: 5 * time.Minute,
		Polling:     5 * time.Second,
		Cloudflare:  config.Cloudflare{APIToken: fakeCloudflareToken},
		Route53: config.Route53{
			Region:          "us-east-1",
			HostedZoneID:    "Z0123456789ABCDEFGHIJ",
			AccessKeyID:     fakeAWSAccessKeyID,
			SecretAccessKey: fakeAWSSecretKey,
			SessionToken:    "fake-session-token",
		},
	}

	cf := cloudflareConfig(dnsCfg)
	if cf.AuthToken != fakeCloudflareToken {
		t.Errorf("AuthToken = %q, want the configured token", cf.AuthToken)
	}
	// The token path only; the legacy email+global-key pair must stay empty, or lego builds the
	// client around a credential this program never configured.
	if cf.AuthEmail != "" || cf.AuthKey != "" {
		t.Errorf("AuthEmail/AuthKey must stay empty when a scoped token is used, got %q/%q",
			cf.AuthEmail, cf.AuthKey)
	}
	if cf.TTL != 600 || cf.PropagationTimeout != dnsCfg.Propagation || cf.PollingInterval != dnsCfg.Polling {
		t.Errorf("the config must carry what the caller passed, got %+v", cf)
	}
	if cf.HTTPClient == nil || cf.HTTPClient.Timeout <= 0 {
		t.Errorf("the cloudflare client's timeout is %v: Present and CleanUp hold the per-name TXT "+
			"lease mutex across the call, so a request with no deadline wedges every certificate "+
			"sharing the challenge FQDN", cf.HTTPClient)
	}

	r53 := route53Config(dnsCfg)
	if r53.Region != "us-east-1" || r53.HostedZoneID != "Z0123456789ABCDEFGHIJ" {
		t.Errorf("region and hosted zone must be carried, got %q/%q", r53.Region, r53.HostedZoneID)
	}
	if r53.AccessKeyID != fakeAWSAccessKeyID || r53.SecretAccessKey != fakeAWSSecretKey ||
		r53.SessionToken != "fake-session-token" {
		t.Errorf("the static credential pair must be carried, got %+v", r53)
	}
	if r53.TTL != 600 || r53.PropagationTimeout != dnsCfg.Propagation || r53.PollingInterval != dnsCfg.Polling {
		t.Errorf("the config must carry what the caller passed, got %+v", r53)
	}
	// lego's own defaults, which a struct literal would have dropped: retries matter because Route
	// 53 throttles at 5 requests/second per account, and the wait matters because the API returns
	// before the change is visible.
	if r53.MaxRetries != 5 {
		t.Errorf("MaxRetries = %d, want lego's default 5", r53.MaxRetries)
	}
	if !r53.WaitForRecordSetsChanged {
		t.Error("WaitForRecordSetsChanged must stay true: the Route 53 API returns before the " +
			"record change is INSYNC")
	}

	// AWS_HOSTED_ZONE_ID is lego's own fallback, and it survives an empty config field -- an
	// operator moving off `dns.provider: lego` + `legoProvider: route53` keeps the zone they pinned.
	t.Setenv("AWS_HOSTED_ZONE_ID", "Z0123456789ABCDEFGHIJ")
	chainCfg := config.DNS{TTL: 600, Propagation: 5 * time.Minute, Polling: 5 * time.Second}
	if got := route53Config(chainCfg).HostedZoneID; got != "Z0123456789ABCDEFGHIJ" {
		t.Errorf("HostedZoneID = %q, want lego's AWS_HOSTED_ZONE_ID fallback", got)
	}
	// And an empty config must leave the credential fields empty, which is what selects the SDK's
	// default chain instead of a static provider built from an empty pair.
	chain := route53Config(chainCfg)
	if chain.AccessKeyID != "" || chain.SecretAccessKey != "" || chain.SessionToken != "" {
		t.Errorf("no static credential is configured, so none may be invented: got %+v", chain)
	}
}

// A token-file Cloudflare provider must outlive the call that created the record, and must still
// be rebuilt when the file changes.
//
// lego's cloudflare provider deletes a record by the ID it remembered when it created it, keyed by
// the challenge token (providers/dns/cloudflare/cloudflare.go: Present stores d.recordIDs[token],
// CleanUp looks it up and answers "cloudflare: unknown record ID" when the key is gone). A provider
// built between Present and CleanUp has an empty map, so CleanUp fails and the TXT record stays in
// the zone. Staging runs showed exactly that: every issuance left one _acme-challenge TXT behind,
// and a leftover is what a later validation can be answered from -- "During secondary validation:
// Incorrect TXT record ... found".
//
// The other half is the reason the provider was rebuilt on every call in the first place, so it has
// to be pinned too: a rotated token file must produce a new provider without a restart, or every
// Present fails 401/403 until the daemon is restarted.
func TestCloudflareTokenFileKeepsOneProviderUntilTheTokenChanges(t *testing.T) {
	clearProviderEnv(t)

	tokenFile := filepath.Join(t.TempDir(), "cloudflare.token")
	if err := os.WriteFile(tokenFile, []byte(fakeCloudflareToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := writeSolverConfig(t, `  provider: cloudflare
  cloudflare:
    apiTokenFile: `+tokenFile+`
`)
	solver, err := NewDNSSolver(cfg.DNS, cfg.Tencent, slog.New(slog.NewTextHandler(io.Discard, nil)))
	assertNotARebuildHint(t, config.DNSProviderCloudflare, err)

	first, err := solver.newProvider(context.Background())
	if err != nil {
		t.Fatalf("building the cloudflare provider from the token file: %v", err)
	}
	second, err := solver.newProvider(context.Background())
	if err != nil {
		t.Fatalf("building the cloudflare provider a second time: %v", err)
	}
	if first != second {
		t.Fatal("two calls with an unchanged token file returned different cloudflare providers.\n" +
			"lego's provider deletes a record by the ID it remembered at Present, keyed by the " +
			"challenge token, so a provider rebuilt between Present and CleanUp cannot delete the " +
			"record it created: CleanUp fails with \"cloudflare: unknown record ID\" and the TXT " +
			"stays in the operator's zone.")
	}

	// A rotated or revoked token must take effect without a restart.
	const rotated = "fake-cloudflare-scoped-token-rotated"
	if err := os.WriteFile(tokenFile, []byte(rotated+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	third, err := solver.newProvider(context.Background())
	if err != nil {
		t.Fatalf("building the cloudflare provider after a token rotation: %v", err)
	}
	if third == first {
		t.Fatal("the token file changed and the same cloudflare provider came back: a rotated " +
			"token would never take effect, every Present would fail 401/403 until the daemon " +
			"restarts, and consecutive failures walk the identifier budget toward a CA pause")
	}

	// The cache is per token, not "the last one that was built": going back to the previous token
	// must build again rather than hand out the provider that no longer matches the file.
	if err := os.WriteFile(tokenFile, []byte(fakeCloudflareToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fourth, err := solver.newProvider(context.Background())
	if err != nil {
		t.Fatalf("building the cloudflare provider after the token was restored: %v", err)
	}
	if fourth == third {
		t.Fatal("the token file went back to the first token and the provider for the rotated one " +
			"was returned: the instance has to match the credential the file holds")
	}
}
