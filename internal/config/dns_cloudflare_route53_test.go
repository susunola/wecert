package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// clearDNSProviderEnv blanks the environment fallbacks the two new providers read, so a variable
// exported for some other tool on the machine running the tests cannot decide the outcome.
func clearDNSProviderEnv(t *testing.T) {
	t.Helper()
	for _, env := range []string{
		EnvCloudflareAPIToken, EnvCloudflareAPITokenAlt, EnvAWSRegion, EnvAWSDefaultRegion,
	} {
		t.Setenv(env, "")
	}
}

// Both providers must be selectable in a default build.
//
// This is the config half of the bug the change fixes: `dns.provider: cloudflare` used to exist
// only as `dns.provider: lego` + `dns.legoProvider: cloudflare`, which a default binary refuses
// with the "rebuild with -tags lego_dns" instruction -- so using Cloudflare meant compiling in all
// ~198 lego providers and their hundreds of SDKs. The other half (that the solver is built, and
// that the refusal message is gone) lives in internal/acme/dns_cloudflare_route53_test.go.
func TestCloudflareAndRoute53AreAcceptedInTheDefaultBuild(t *testing.T) {
	clearDNSProviderEnv(t)

	cf, err := Load(writeConfig(t, minimalWithDNS+`
dns:
  provider: cloudflare
  cloudflare:
    apiToken: fake-cloudflare-token
`))
	if err != nil {
		t.Fatalf("a cloudflare config must load in the default build: %v", err)
	}
	if cf.DNS.Provider != DNSProviderCloudflare {
		t.Errorf("provider = %q, want %q", cf.DNS.Provider, DNSProviderCloudflare)
	}
	if cf.DNS.Cloudflare.APIToken != "fake-cloudflare-token" {
		t.Errorf("apiToken = %q, want what the file set", cf.DNS.Cloudflare.APIToken)
	}

	// No static keys: the AWS default chain is a valid credential source, so this must load.
	r53, err := Load(writeConfig(t, minimalWithDNS+`
dns:
  provider: route53
  route53:
    region: us-east-1
`))
	if err != nil {
		t.Fatalf("a route53 config using the AWS default chain must load in the default build: %v", err)
	}
	if r53.DNS.Provider != DNSProviderRoute53 {
		t.Errorf("provider = %q, want %q", r53.DNS.Provider, DNSProviderRoute53)
	}
	if r53.DNS.Route53.Region != "us-east-1" {
		t.Errorf("region = %q, want us-east-1", r53.DNS.Route53.Region)
	}
}

// A Cloudflare token that is nowhere to be found is named, with both places to put it.
//
// The whole reason these two are native rather than generic `lego` entries is that a config that
// cannot work is refused at load, by name. Letting it through would fail at provider construction
// -- after the ACME account had been touched -- and lego's own message ("invalid credentials:
// authEmail, authKey or authToken must be set") names a setting this program does not have.
func TestCloudflareTokenMustComeFromSomewhere(t *testing.T) {
	clearDNSProviderEnv(t)

	_, err := Load(writeConfig(t, minimalWithDNS+`
dns:
  provider: cloudflare
`))
	if err == nil {
		t.Fatal("provider=cloudflare without a token must be refused at load time")
	}
	for _, want := range []string{"dns.cloudflare.apiToken", EnvCloudflareAPIToken, EnvCloudflareAPITokenAlt} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must name %q so the operator can act on it, got %q", want, err)
		}
	}
}

// Route 53 needs a region, but must NOT need credentials: an EC2 instance role supplies those.
//
// Requiring accessKeyId + secretAccessKey here would be the easy mistake, and it would make the
// best credential source in AWS -- the instance profile, which never writes a key to disk -- the
// one deployment shape that cannot use this provider.
func TestRoute53RequiresARegionButNotStaticKeys(t *testing.T) {
	clearDNSProviderEnv(t)

	_, err := Load(writeConfig(t, minimalWithDNS+`
dns:
  provider: route53
`))
	if err == nil {
		t.Fatal("provider=route53 without a region must be refused: the SDK cannot sign a request " +
			"without one, and the failure would arrive after an order had been placed")
	}
	for _, want := range []string{"dns.route53.region", EnvAWSRegion, EnvAWSDefaultRegion} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must name %q, got %q", want, err)
		}
	}

	// AWS_REGION stands in for the config field, the same way CLOUDFLARE_DNS_API_TOKEN stands in
	// for the Cloudflare token.
	t.Setenv(EnvAWSRegion, "eu-west-1")
	cfg, err := Load(writeConfig(t, minimalWithDNS+`
dns:
  provider: route53
`))
	if err != nil {
		t.Fatalf("AWS_REGION must satisfy the region requirement: %v", err)
	}
	if cfg.DNS.Route53.Region != "eu-west-1" {
		t.Errorf("region = %q, want the environment value, so validation and the provider agree",
			cfg.DNS.Route53.Region)
	}

	// And the chain case stays a chain case: nothing is filled into the credential fields, or lego
	// would build a static provider out of an empty pair instead of loading the default chain.
	t.Setenv(EnvAWSRegion, "")
	cfg, err = Load(writeConfig(t, minimalWithDNS+`
dns:
  provider: route53
  route53:
    region: us-east-1
    hostedZoneId: Z0123456789ABCDEFGHIJ
`))
	if err != nil {
		t.Fatalf("a region plus a pinned zone must load: %v", err)
	}
	if cfg.DNS.Route53.AccessKeyID != "" || cfg.DNS.Route53.SecretAccessKey != "" {
		t.Errorf("no static key is configured, so none may be invented: got %q/%q",
			cfg.DNS.Route53.AccessKeyID, cfg.DNS.Route53.SecretAccessKey)
	}
	if cfg.DNS.Route53.HostedZoneID != "Z0123456789ABCDEFGHIJ" {
		t.Errorf("hostedZoneId = %q", cfg.DNS.Route53.HostedZoneID)
	}
}

// Half a static pair is not a credential source; it is a config that cannot work.
//
// lego refuses it too, but only when the solver is built, in words that name neither setting
// ("AccessKeyID and SecretAccessKey must be supplied together"). The same applies to a session
// token with no pair to carry: with the default chain the SDK fetches its own.
func TestRoute53StaticKeysMustBePaired(t *testing.T) {
	clearDNSProviderEnv(t)

	cases := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "key id without the secret",
			body: "    accessKeyId: AKIAIOSFODNN7EXAMPLE\n",
			want: []string{"dns.route53.accessKeyId", "dns.route53.secretAccessKey"},
		},
		{
			name: "secret without the key id",
			body: "    secretAccessKey: fake-secret\n",
			want: []string{"dns.route53.secretAccessKey", "dns.route53.accessKeyId"},
		},
		{
			name: "session token without a pair",
			body: "    sessionToken: fake-session\n",
			want: []string{"dns.route53.sessionToken"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, minimalWithDNS+`
dns:
  provider: route53
  route53:
    region: us-east-1
`+tc.body))
			if err == nil {
				t.Fatalf("%s must be refused at load time", tc.name)
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal must name %q, got %q", want, err)
				}
			}
		})
	}

	// The complete static set loads, session token included.
	cfg, err := Load(writeConfig(t, minimalWithDNS+`
dns:
  provider: route53
  route53:
    region: us-east-1
    accessKeyId: AKIAIOSFODNN7EXAMPLE
    secretAccessKey: fake-secret
    sessionToken: fake-session
`))
	if err != nil {
		t.Fatalf("a complete static pair plus session token must load: %v", err)
	}
	if cfg.DNS.Route53.SessionToken != "fake-session" {
		t.Errorf("SessionToken = %q", cfg.DNS.Route53.SessionToken)
	}
}

// A provider block under the wrong provider is rejected, naming both.
//
// The fields are read only by their own provider, so `cloudflare: {apiToken: ...}` next to
// `provider: dnspod` means the operator believes challenges go through Cloudflare while they
// actually go through DNSPod -- the same call dns.legoProvider already gets.
func TestProviderBlocksUnderTheWrongProviderAreRejected(t *testing.T) {
	clearDNSProviderEnv(t)

	cases := []struct {
		name     string
		body     string
		wantBoth []string
	}{
		{
			name: "cloudflare block under dnspod",
			body: strings.Replace(minimalPrefix, "  loginToken: token\n",
				"  loginToken: token\n  cloudflare:\n    apiToken: fake-cloudflare-token\n", 1),
			wantBoth: []string{"dns.cloudflare", DNSProviderCloudflare, DNSProviderDNSPod},
		},
		{
			name: "route53 block under tencentcloud",
			body: minimalWithDNS + `
dns:
  provider: tencentcloud
  route53:
    region: us-east-1
`,
			wantBoth: []string{"dns.route53", DNSProviderRoute53, DNSProviderTencentCloud},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := loadWithCertificates(t, tc.body)
			if err == nil {
				t.Fatal("a provider block that belongs to another provider must be refused: its " +
					"settings would be silently ignored")
			}
			for _, want := range tc.wantBoth {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal must name %q (both the block and the selected provider), "+
						"got %q", want, err)
				}
			}
		})
	}
}

// loadWithCertificates loads a body that may or may not already carry a certificates block.
func loadWithCertificates(t *testing.T, body string) error {
	t.Helper()
	if !strings.Contains(body, "certificates:") {
		body += `certificates:
  - name: example-com
    domains: ["example.com"]
`
	}
	_, err := Load(writeConfig(t, body))
	return err
}

// An unrelated variable in the environment must not turn a working config into a load error.
//
// The provider blocks are gated on dns.provider before the environment fallbacks are read, because
// otherwise a host that exports CLOUDFLARE_DNS_API_TOKEN for some other tool (or AWS_ACCESS_KEY_ID
// for the AWS CLI) would fill in dns.cloudflare.apiToken on a dnspod config, and the
// wrong-provider check above would refuse it.
func TestForeignProviderEnvVarsDoNotBreakAnotherProvider(t *testing.T) {
	t.Setenv(EnvCloudflareAPIToken, "fake-cloudflare-token")
	t.Setenv(EnvCloudflareAPITokenAlt, "fake-cloudflare-token")
	t.Setenv(EnvAWSRegion, "us-east-1")
	t.Setenv(EnvAWSDefaultRegion, "us-east-1")

	if _, err := Load(writeConfig(t, minimalPrefix+`certificates:
  - name: example-com
    domains: ["example.com"]
`)); err != nil {
		t.Fatalf("a dnspod config must load while Cloudflare/AWS variables are exported: %v", err)
	}
}

// A credential in config.yaml is a credential in every backup of it: the same three ways out the
// DNSPod token has must exist for the Cloudflare token.
func TestCloudflareAPITokenCanComeFromAFileOrTheEnvironment(t *testing.T) {
	const token = "fake-cloudflare-scoped-token"

	t.Run("from a file", func(t *testing.T) {
		clearDNSProviderEnv(t)
		secret := filepath.Join(t.TempDir(), "cloudflare.token")
		if err := os.WriteFile(secret, []byte(token+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(writeConfig(t, minimalWithDNS+`
dns:
  provider: cloudflare
  cloudflare:
    apiTokenFile: `+secret+`
`))
		if err != nil {
			t.Fatalf("a token read from a file must be accepted: %v", err)
		}
		if cfg.DNS.Cloudflare.APIToken != token {
			t.Errorf("APIToken = %q, want the file's contents with the newline trimmed",
				cfg.DNS.Cloudflare.APIToken)
		}
	})

	t.Run("from a systemd credential path", func(t *testing.T) {
		clearDNSProviderEnv(t)
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "cloudflare-token"), []byte(token), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("CREDENTIALS_DIRECTORY", dir)
		cfg, err := Load(writeConfig(t, minimalWithDNS+`
dns:
  provider: cloudflare
  cloudflare:
    apiTokenFile: ${CREDENTIALS_DIRECTORY}/cloudflare-token
`))
		if err != nil {
			t.Fatalf("a LoadCredential path must be accepted: %v", err)
		}
		if cfg.DNS.Cloudflare.APIToken != token {
			t.Errorf("APIToken = %q, want the credential's contents", cfg.DNS.Cloudflare.APIToken)
		}
	})

	for _, env := range []string{EnvCloudflareAPIToken, EnvCloudflareAPITokenAlt} {
		t.Run("from "+env, func(t *testing.T) {
			clearDNSProviderEnv(t)
			t.Setenv(env, token)
			cfg, err := Load(writeConfig(t, minimalWithDNS+`
dns:
  provider: cloudflare
`))
			if err != nil {
				t.Fatalf("%s must be accepted: %v", env, err)
			}
			if cfg.DNS.Cloudflare.APIToken != token {
				t.Errorf("APIToken = %q, want the environment value", cfg.DNS.Cloudflare.APIToken)
			}
		})
	}

	t.Run("a typo'd path fails where the operator can fix it", func(t *testing.T) {
		clearDNSProviderEnv(t)
		_, err := Load(writeConfig(t, minimalWithDNS+`
dns:
  provider: cloudflare
  cloudflare:
    apiTokenFile: /nonexistent/cloudflare.token
`))
		if err == nil || !strings.Contains(err.Error(), "cloudflare.token") {
			t.Errorf("an unreadable secret file must be a config error naming the path, got %v", err)
		}
	})

	t.Run("an empty file is refused", func(t *testing.T) {
		clearDNSProviderEnv(t)
		empty := filepath.Join(t.TempDir(), "empty.token")
		if err := os.WriteFile(empty, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Load(writeConfig(t, minimalWithDNS+`
dns:
  provider: cloudflare
  cloudflare:
    apiTokenFile: `+empty+`
`))
		if err == nil || !strings.Contains(err.Error(), "empty") {
			t.Errorf("a blank credential must be refused here, not by the provider, got %v", err)
		}
	})

	t.Run("setting both is ambiguous and refused", func(t *testing.T) {
		clearDNSProviderEnv(t)
		_, err := Load(writeConfig(t, minimalWithDNS+`
dns:
  provider: cloudflare
  cloudflare:
    apiToken: `+token+`
    apiTokenFile: /etc/wecert/cloudflare.token
`))
		if err == nil || !strings.Contains(err.Error(), "both set") {
			t.Errorf("two sources for one secret must be refused, got %v", err)
		}
	})
}

// The Route 53 secret key gets the same file treatment, and the pair is complete once the file is
// read -- which is what makes a `accessKeyId` in the config plus a `secretAccessKeyFile` a valid
// static credential set rather than half of one.
func TestRoute53SecretAccessKeyCanComeFromAFile(t *testing.T) {
	const secretKey = "fake-aws-secret-access-key"

	t.Run("from a file, completing the pair", func(t *testing.T) {
		clearDNSProviderEnv(t)
		secret := filepath.Join(t.TempDir(), "aws-secret")
		if err := os.WriteFile(secret, []byte(secretKey+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(writeConfig(t, minimalWithDNS+`
dns:
  provider: route53
  route53:
    region: us-east-1
    accessKeyId: AKIAIOSFODNN7EXAMPLE
    secretAccessKeyFile: `+secret+`
`))
		if err != nil {
			t.Fatalf("a key pair completed by a file must be accepted: %v", err)
		}
		if cfg.DNS.Route53.SecretAccessKey != secretKey {
			t.Errorf("SecretAccessKey = %q, want the file's contents with the newline trimmed",
				cfg.DNS.Route53.SecretAccessKey)
		}
	})

	t.Run("from a systemd credential path", func(t *testing.T) {
		clearDNSProviderEnv(t)
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "aws-secret"), []byte(secretKey), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("CREDENTIALS_DIRECTORY", dir)
		cfg, err := Load(writeConfig(t, minimalWithDNS+`
dns:
  provider: route53
  route53:
    region: us-east-1
    accessKeyId: AKIAIOSFODNN7EXAMPLE
    secretAccessKeyFile: ${CREDENTIALS_DIRECTORY}/aws-secret
`))
		if err != nil {
			t.Fatalf("a LoadCredential path must be accepted: %v", err)
		}
		if cfg.DNS.Route53.SecretAccessKey != secretKey {
			t.Errorf("SecretAccessKey = %q, want the credential's contents", cfg.DNS.Route53.SecretAccessKey)
		}
	})

	t.Run("a session token file is read too", func(t *testing.T) {
		clearDNSProviderEnv(t)
		secret := filepath.Join(t.TempDir(), "aws-session")
		if err := os.WriteFile(secret, []byte("fake-session-token\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(writeConfig(t, minimalWithDNS+`
dns:
  provider: route53
  route53:
    region: us-east-1
    accessKeyId: AKIAIOSFODNN7EXAMPLE
    secretAccessKey: fake-secret
    sessionTokenFile: `+secret+`
`))
		if err != nil {
			t.Fatalf("a session token file must be accepted: %v", err)
		}
		if cfg.DNS.Route53.SessionToken != "fake-session-token" {
			t.Errorf("SessionToken = %q", cfg.DNS.Route53.SessionToken)
		}
	})

	t.Run("setting both is ambiguous and refused", func(t *testing.T) {
		clearDNSProviderEnv(t)
		_, err := Load(writeConfig(t, minimalWithDNS+`
dns:
  provider: route53
  route53:
    region: us-east-1
    accessKeyId: AKIAIOSFODNN7EXAMPLE
    secretAccessKey: fake-secret
    secretAccessKeyFile: /etc/wecert/aws-secret
`))
		if err == nil || !strings.Contains(err.Error(), "both set") {
			t.Errorf("two sources for one secret must be refused, got %v", err)
		}
	})

	t.Run("an empty file is refused", func(t *testing.T) {
		clearDNSProviderEnv(t)
		empty := filepath.Join(t.TempDir(), "empty")
		if err := os.WriteFile(empty, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Load(writeConfig(t, minimalWithDNS+`
dns:
  provider: route53
  route53:
    region: us-east-1
    accessKeyId: AKIAIOSFODNN7EXAMPLE
    secretAccessKeyFile: `+empty+`
`))
		if err == nil || !strings.Contains(err.Error(), "empty") {
			t.Errorf("a blank credential must be refused here, not by the provider, got %v", err)
		}
	})
}

// Cloudflare refuses a TTL below 120s, so a config that lowers dns.ttl is refused by name.
//
// The default of 600 is above the floor, so this only meets an operator who lowered it to speed up
// propagation -- and the failure it prevents arrives at startup from lego ("cloudflare: invalid
// TTL"), naming neither dns.ttl nor the floor.
func TestCloudflareTTLFloorIsRefusedAtLoadTime(t *testing.T) {
	clearDNSProviderEnv(t)

	body := func(ttl string) string {
		return minimalWithDNS + `
dns:
  provider: cloudflare
  ttl: ` + ttl + `
  cloudflare:
    apiToken: fake-cloudflare-token
`
	}

	_, err := Load(writeConfig(t, body("60")))
	if err == nil || !strings.Contains(err.Error(), "dns.ttl") || !strings.Contains(err.Error(), "120") {
		t.Errorf("a TTL under Cloudflare's floor must be refused, naming the field and the floor, got %v", err)
	}

	// The floor itself and the default both load, and the check must not leak onto dnspod, whose
	// paid tiers may go below 120 (its own floor is a per-tier API limit, not a protocol one).
	if _, err := Load(writeConfig(t, body("120"))); err != nil {
		t.Errorf("a TTL of exactly 120 must be accepted: %v", err)
	}
	if _, err := Load(writeConfig(t, strings.Replace(minimalPrefix, "  loginToken: token\n",
		"  loginToken: token\n  ttl: 60\n", 1)+`certificates:
  - name: example-com
    domains: ["example.com"]
`)); err != nil {
		t.Errorf("the cloudflare floor must not be applied to dnspod: %v", err)
	}
}

// A session token FILE without a static pair must be refused, the same as the inline field.
//
// The inline case is in TestRoute53StaticKeysMustBePaired; this is the file variant. resolve()
// fills SessionToken from the file first, so the pair check sees a value and refuses -- but that
// path is easy to break by checking the file field instead of the resolved one.
func TestSessionTokenFileWithoutAStaticPairIsRefused(t *testing.T) {
	clearDNSProviderEnv(t)

	secret := filepath.Join(t.TempDir(), "session")
	if err := os.WriteFile(secret, []byte("fake-session\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Load(writeConfig(t, minimalWithDNS+`
dns:
  provider: route53
  route53:
    region: us-east-1
    sessionTokenFile: `+secret+`
`))
	if err == nil {
		t.Fatal("sessionTokenFile without a static key pair must be refused at load time")
	}
	if !strings.Contains(err.Error(), "dns.route53.sessionToken") {
		t.Errorf("the refusal must name dns.route53.sessionToken, got %q", err)
	}
}

// The *_file credential paths are documented as 0600. A wider file is a warning, not a
// refusal -- the same call configPermWarnings makes for an inline secret in a 0644 config.
func TestSecretFilePermissionsAreWarnedAbout(t *testing.T) {
	// Pure helper, like configPermWarnings: wording is the contract.
	if w := secretFilePermWarnings("dns.loginToken", "/etc/wecert/tok", 0o600); len(w) != 0 {
		t.Errorf("0600 must not warn, got %v", w)
	}
	if w := secretFilePermWarnings("dns.loginToken", "/etc/wecert/tok", 0o400); len(w) != 0 {
		t.Errorf("0400 (systemd LoadCredential) must not warn, got %v", w)
	}
	if w := secretFilePermWarnings("dns.cloudflare.apiToken", "/etc/wecert/cf", 0o644); len(w) != 1 {
		t.Fatalf("0644 must warn, got %v", w)
	} else if !strings.Contains(w[0], "dns.cloudflare.apiToken") || !strings.Contains(w[0], "0644") {
		t.Errorf("the warning must name the field and the mode, got %q", w[0])
	}
	if w := secretFilePermWarnings("dns.route53.secretAccessKey", "/run/cred/sk", 0o640); len(w) != 1 {
		t.Errorf("0640 must warn (group-readable), got %v", w)
	}

	// End to end: Load surfaces the warning for a wide secret file (it still loads).
	clearDNSProviderEnv(t)
	wide := filepath.Join(t.TempDir(), "cf-token")
	if err := os.WriteFile(wide, []byte("fake-cloudflare-token\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(writeConfig(t, minimalWithDNS+`
dns:
  provider: cloudflare
  cloudflare:
    apiTokenFile: `+wide+`
`)); err != nil {
		t.Fatalf("a wide secret file must still load (warn, not refuse): %v", err)
	}
}
