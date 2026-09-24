// Package config defines wecert's declarative desired state (the spec).
//
// Design principle: the YAML says only "what I want" and carries no runtime
// state at all. Runtime state (order URL, ARI window, Tencent Cloud CertId and
// so on) always goes into SQLite, because losing it directly causes duplicate
// orders and runs into Let's Encrypt rate limits.
package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// Split out so one concern lives in one file. Same package.

func (c *Config) normalize() error {
	if err := c.normalizeRoot(); err != nil {
		return err
	}
	if err := c.normalizeDNS(); err != nil {
		return err
	}
	if err := c.normalizeListeners(); err != nil {
		return err
	}
	if err := c.normalizeTencent(); err != nil {
		return err
	}
	if err := c.normalizeDeployTarget(); err != nil {
		return err
	}
	if err := c.normalizeSubsections(); err != nil {
		return err
	}
	return c.normalizeCertificatesBlock()
}

// normalizeRoot validates the process identity: where state lives and who the CA
// account is.
func (c *Config) normalizeRoot() error {
	if c.StatePath == "" {
		return fmt.Errorf("statePath is required")
	}
	if c.ACME.Directory == "" {
		return fmt.Errorf("acme.directory is required")
	}
	seenDirectories := map[string]bool{c.ACME.Directory: true}
	for i, directory := range c.ACME.FallbackDirectories {
		directory = strings.TrimSpace(directory)
		if directory == "" {
			return fmt.Errorf("acme.fallbackDirectories[%d] is empty", i)
		}
		u, err := url.Parse(directory)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("acme.fallbackDirectories[%d] must be an absolute https URL, got %q", i, directory)
		}
		if seenDirectories[directory] {
			return fmt.Errorf("acme.fallbackDirectories[%d] duplicates %q", i, directory)
		}
		seenDirectories[directory] = true
		c.ACME.FallbackDirectories[i] = directory
	}
	if c.ACME.Email == "" {
		return fmt.Errorf("acme.email is required")
	}
	if (c.ACME.EAB.KID == "") != (c.ACME.EAB.HMAC == "") {
		return fmt.Errorf("acme.eab.kid and acme.eab.hmac (or hmacFile) must be set together")
	}
	return validateContactEmail(c.ACME.Email)
}

// normalizeDNS picks the DNS-01 provider and the propagation knobs. Provider first:
// every later field is only meaningful relative to which API will write the TXT.
func (c *Config) normalizeDNS() error {
	// The DNS provider must be chosen explicitly. Defaulting to dnspod suggests
	// Tencent Cloud AK/SK would be enough, then fails confusingly at the DNS-01
	// step.
	switch c.DNS.Provider {
	case "":
		c.DNS.Provider = DNSProviderDNSPod
	case DNSProviderDNSPod, DNSProviderTencentCloud, DNSProviderCloudflare, DNSProviderRoute53:
	case DNSProviderLego:
		if c.DNS.LegoProvider == "" {
			return fmt.Errorf("dns.provider=%q requires dns.legoProvider to name one of lego's DNS "+
				"providers (e.g. cloudflare, route53, alidns); that provider then reads its own "+
				"credentials from the environment, using lego's documented variable names",
				DNSProviderLego)
		}
		if !acmeSupportsLegoProviders {
			return fmt.Errorf("dns.provider=%q needs a binary built with -tags lego_dns: the default "+
				"build carries only the native dnspod, tencentcloud, cloudflare and route53 "+
				"providers, because lego's registry pulls in hundreds of third-party SDKs -- "+
				"cloudflare and route53 are native, so they need no tag", DNSProviderLego)
		}
	default:
		return fmt.Errorf("dns.provider must be %q, %q, %q, %q or %q, got %q",
			DNSProviderDNSPod, DNSProviderTencentCloud, DNSProviderCloudflare, DNSProviderRoute53,
			DNSProviderLego, c.DNS.Provider)
	}
	// legoProvider is read only when provider is "lego". Leaving it set next to a native
	// provider means the operator believes challenges go through, say, Cloudflare while they
	// actually go through dnspod -- rejected loudly rather than silently ignored, for the same
	// reason desiredState.path under mode=static is rejected above.
	if c.DNS.Provider != DNSProviderLego && c.DNS.LegoProvider != "" {
		return fmt.Errorf("dns.legoProvider is set but dns.provider is %q: the field is only read "+
			"when dns.provider=%q, so it would be silently ignored -- remove it, or switch "+
			"dns.provider to %q if lego's registry is what you meant",
			c.DNS.Provider, DNSProviderLego, DNSProviderLego)
	}
	// The same rule for the two provider blocks added here: their fields are read only when their
	// provider is the selected one, so under any other provider the operator would be configuring a
	// Cloudflare token (or an AWS key) that nothing reads, while believing the challenges go
	// through it -- they would actually go through the selected provider.
	if c.DNS.Provider != DNSProviderCloudflare && c.DNS.Cloudflare.configured() {
		return fmt.Errorf("dns.cloudflare is set but dns.provider is %q: the block is only read "+
			"when dns.provider=%q, so the token in it would be silently ignored -- remove it, or "+
			"set dns.provider to %q if Cloudflare is what you meant",
			c.DNS.Provider, DNSProviderCloudflare, DNSProviderCloudflare)
	}
	if c.DNS.Provider != DNSProviderRoute53 && c.DNS.Route53.configured() {
		return fmt.Errorf("dns.route53 is set but dns.provider is %q: the block is only read when "+
			"dns.provider=%q, so the credentials and hosted zone in it would be silently ignored "+
			"-- remove it, or set dns.provider to %q if Route 53 is what you meant",
			c.DNS.Provider, DNSProviderRoute53, DNSProviderRoute53)
	}
	if c.DNS.Provider == DNSProviderDNSPod && c.DNS.LoginToken == "" {
		return fmt.Errorf("dns.provider=dnspod requires dns.loginToken, dns.loginTokenFile or " +
			"$" + EnvDNSPodLoginToken + " " +
			"(a DNSPod API token, not a Tencent Cloud SecretId/SecretKey;" +
			"to use Tencent Cloud CAM credentials instead, set dns.provider=tencentcloud)")
	}
	if c.DNS.Provider == DNSProviderCloudflare && c.DNS.Cloudflare.APIToken == "" {
		return fmt.Errorf("dns.provider=cloudflare requires dns.cloudflare.apiToken, "+
			"dns.cloudflare.apiTokenFile or $%s (or its alias $%s): a scoped API token with "+
			"Zone:Read and DNS:Edit on the zone that holds the challenge names",
			EnvCloudflareAPIToken, EnvCloudflareAPITokenAlt)
	}
	if c.DNS.Provider == DNSProviderRoute53 {
		if c.DNS.Route53.Region == "" {
			return fmt.Errorf("dns.provider=route53 requires dns.route53.region or $%s (or $%s): "+
				"the AWS SDK refuses to sign a request without a region, so the challenge would "+
				"fail only after an order had already been placed",
				EnvAWSRegion, EnvAWSDefaultRegion)
		}
		// The static pair is all-or-nothing. lego refuses half a pair as well, but only when the
		// solver is built -- after config load, and in its own words ("AccessKeyID and
		// SecretAccessKey must be supplied together"), which name neither setting.
		switch {
		case c.DNS.Route53.AccessKeyID != "" && c.DNS.Route53.SecretAccessKey == "":
			return fmt.Errorf("dns.route53.accessKeyId is set but the secret key is missing: add " +
				"dns.route53.secretAccessKey or dns.route53.secretAccessKeyFile, or remove " +
				"accessKeyId to use the AWS default chain (environment, shared config, or the " +
				"instance role)")
		case c.DNS.Route53.AccessKeyID == "" && c.DNS.Route53.SecretAccessKey != "":
			return fmt.Errorf("dns.route53.secretAccessKey is set but dns.route53.accessKeyId is " +
				"missing: add the key id, or remove the secret key to use the AWS default chain " +
				"(environment, shared config, or the instance role)")
		case c.DNS.Route53.SessionToken != "" && c.DNS.Route53.AccessKeyID == "":
			return fmt.Errorf("dns.route53.sessionToken is set without a static key pair: the " +
				"token only belongs to dns.route53.accessKeyId + dns.route53.secretAccessKey, and " +
				"with the AWS default chain the SDK fetches its own -- remove it, or add the pair")
		}
	}

	var err error
	if c.DNS.Propagation, err = parseDuration(c.DNS.PropagationTimeout, 5*time.Minute, "dns.propagationTimeout"); err != nil {
		return err
	}
	if c.DNS.Polling, err = parseDuration(c.DNS.PollingInterval, 5*time.Second, "dns.pollingInterval"); err != nil {
		return err
	}
	// Both of these are only checked to be positive by parseDuration, and both are dangerous at
	// the small end in ways that look harmless in a config file.
	//
	// pollingInterval is how long the propagation wait sleeps between rounds, and each round asks
	// every authoritative nameserver of the zone for every record of that zone. `1ms` is therefore
	// not "check more often", it is a flood of UDP queries at the operator's own DNS provider --
	// the exact thing dns.go's own comment warns gets you rate limited or dropped, which then
	// affects every other DNS user on that host.
	//
	// propagationTimeout is the whole budget for a record to appear. Below the zone's own TTL there
	// is no chance it can: the write is invisible to the resolvers for at least the negative-cache
	// TTL, measured at ~600s on DNSPod. A small value does not fail fast in a useful way; it turns
	// each fresh write into a failed round plus an escalating backoff (1m, 2m, 4m ...), which
	// delays issuance by minutes to hours.
	if c.DNS.Polling < time.Second {
		return fmt.Errorf("dns.pollingInterval is %s, which is below the 1s minimum: each round asks "+
			"every authoritative nameserver of the zone for every record, so a very short interval is "+
			"a burst of queries at your DNS provider rather than a faster check", c.DNS.Polling)
	}
	if c.DNS.Propagation < 30*time.Second {
		return fmt.Errorf("dns.propagationTimeout is %s, which is below the 30s minimum: a zone's "+
			"negative caching alone can hide a fresh record for its SOA TTL (about 600s on DNSPod), "+
			"so a short budget only guarantees a failed round and a backoff", c.DNS.Propagation)
	}
	if c.DNS.Polling >= c.DNS.Propagation {
		return fmt.Errorf("dns.pollingInterval (%s) must be shorter than dns.propagationTimeout (%s): "+
			"the interval is the sleep between rounds inside that budget, so an interval at or above "+
			"it means the propagation wait probes once and gives up", c.DNS.Polling, c.DNS.Propagation)
	}
	if c.DNS.TTL == 0 {
		// The default is 600, not 60: on DNSPod's free tier the TTL floor is 600, and
		// 60 is rejected by the API with LimitExceeded.RecordTtlLimit. Paid tiers may
		// go lower, but the default must hold on every tier.
		c.DNS.TTL = 600
	}
	// A negative TTL is a typo, not "unset" -- the same rule failureFallback.* applies:
	// silently replacing it with the default would throw away the number the operator wrote.
	if c.DNS.TTL < 0 {
		return fmt.Errorf("dns.ttl must not be negative, got %d (0 means \"use the default\")", c.DNS.TTL)
	}
	// Cloudflare's API refuses a TXT TTL below 120 seconds, and lego enforces the same floor when
	// the provider is built. The default of 600 is above it, so this only meets an operator who
	// lowered dns.ttl to speed up propagation -- catching it here names the field, where the
	// startup failure names neither it nor the provider's own floor.
	if c.DNS.Provider == DNSProviderCloudflare && c.DNS.TTL < cloudflareMinTTL {
		return fmt.Errorf("dns.ttl is %d, which is below Cloudflare's %d-second floor: the API "+
			"rejects a shorter TXT TTL, so lowering dns.ttl for a faster propagation round is not "+
			"available on this provider", c.DNS.TTL, cloudflareMinTTL)
	}
	if len(c.DNS.RecursiveNameservers) > 0 {
		resolvers, err := normalizeRecursiveNameservers(c.DNS.RecursiveNameservers)
		if err != nil {
			return err
		}
		c.DNS.RecursiveNameservers = resolvers
	}
	return nil
}

// normalizeListeners validates the two HTTP listeners. Both default to loopback;
// binding further is allowed but warned about at load (see listenWarnings).
func (c *Config) normalizeListeners() error {
	if c.Metrics.Listen == "" {
		c.Metrics.Listen = "127.0.0.1:9800"
	}
	// A malformed listen address used to surface only when the metrics server tried to bind --
	// after the ACME account had been touched. /metrics is this system's only expiry alerting
	// channel, so a typo there must be a load-time error.
	if _, _, err := net.SplitHostPort(c.Metrics.Listen); err != nil {
		return fmt.Errorf("metrics.listen must be a host:port address, got %q: %w", c.Metrics.Listen, err)
	}
	return c.Webhook.normalize()
}

// normalizeTencent validates how credentials are obtained and which regions/types
// the deployer is allowed to touch.
func (c *Config) normalizeTencent() error {
	switch c.Tencent.CredentialMode {
	case "":
		c.Tencent.CredentialMode = CredentialCVMRole
	case CredentialStatic, CredentialCVMRole:
	default:
		return fmt.Errorf("tencent.credentialMode must be %q or %q, got %q",
			CredentialStatic, CredentialCVMRole, c.Tencent.CredentialMode)
	}

	// With credentialMode=static, secretId/secretKey need not live in the config:
	// the TENCENTCLOUD_SECRET_ID / TENCENTCLOUD_SECRET_KEY env vars are accepted
	// too, so no long-lived secret has to appear in the file. The real validation
	// happens in deploy.NewCredentialSource.
	if c.Tencent.CredentialMode == CredentialCVMRole && c.Tencent.RoleName == "" {
		return fmt.Errorf("tencent.credentialMode=cvm-role requires roleName")
	}
	if len(c.Tencent.ResourceTypes) == 0 {
		c.Tencent.ResourceTypes = []string{"clb"}
	}
	if len(c.Tencent.Regions) == 0 {
		return fmt.Errorf("tencent.regions is required (CLB is regional; list every region you have CLBs in)")
	}
	// Both lists are multiplied into the UpdateCertificateInstance request (types x regions) and
	// into the onboarding rule enumeration, so a duplicate costs a bigger request and a typo is only
	// found by the cloud API at deploy time -- the expensive place to learn about one. Every other
	// list in this file is normalised (domains, recursiveNameservers); these two were the exception.
	var err error
	if c.Tencent.Regions, err = normalizeList("tencent.regions", c.Tencent.Regions); err != nil {
		return err
	}
	if c.Tencent.ResourceTypes, err = normalizeList("tencent.resourceTypes", c.Tencent.ResourceTypes); err != nil {
		return err
	}
	return nil
}

// normalizeDeployTarget validates the deploy backend and the nginx layout.
//
// The backend is process-wide (one Deployer); a per-certificate Target can only
// select nginx or inherit. Mixing CLB and nginx in one process is deliberately
// not supported here -- two Deployer halves with two id spaces and two delete
// policies is how a retire/reap loop starts deleting the wrong kind of object.
func (c *Config) normalizeDeployTarget() error {
	if c.Deploy.Target == "" {
		c.Deploy.Target = DeployTargetTencent
	}
	switch c.Deploy.Target {
	case DeployTargetTencent, DeployTargetNginx:
	default:
		return fmt.Errorf("deploy.target must be %q or %q, got %q",
			DeployTargetTencent, DeployTargetNginx, c.Deploy.Target)
	}
	if c.Deploy.Target == DeployTargetNginx || c.nginxMentioned() {
		if err := c.normalizeNginx(); err != nil {
			return err
		}
	}
	for i := range c.Certificates {
		cert := &c.Certificates[i]
		t := cert.Deploy.Target
		if t == "" {
			continue
		}
		if t != DeployTargetTencent && t != DeployTargetNginx {
			return fmt.Errorf("certificate %q: deploy.target must be %q or %q, got %q",
				cert.Name, DeployTargetTencent, DeployTargetNginx, t)
		}
		if t != c.Deploy.Target {
			return fmt.Errorf("certificate %q: deploy.target=%q disagrees with the process "+
				"deploy.target=%q; one process deploys to one backend (split the fleet across two "+
				"configs if both are needed)", cert.Name, t, c.Deploy.Target)
		}
		if cert.Deploy.Nginx != nil && cert.Deploy.Nginx.Dir != "" && t != DeployTargetNginx {
			return fmt.Errorf("certificate %q: deploy.nginx.dir is set but deploy.target is %q; "+
				"the block is only read when deploying to nginx", cert.Name, t)
		}
	}
	// An nginx block with deploy.target=tencent is the same silent-ignore trap as
	// dns.cloudflare under dnspod: the operator believes files will be written.
	if c.Deploy.Target != DeployTargetNginx && c.nginxMentioned() {
		return fmt.Errorf("nginx: is set but deploy.target is %q: the block is only read when "+
			"deploy.target=%q, so the paths and reload command would be silently ignored -- "+
			"remove it, or set deploy.target to %q if nginx is what you meant",
			c.Deploy.Target, DeployTargetNginx, DeployTargetNginx)
	}
	return nil
}

func (c *Config) nginxMentioned() bool {
	return c.Nginx.DirTemplate != "" || c.Nginx.CertFile != "" || c.Nginx.KeyFile != "" ||
		len(c.Nginx.Reload) > 0
}

func (c *Config) normalizeNginx() error {
	if c.Nginx.DirTemplate == "" {
		c.Nginx.DirTemplate = "/etc/nginx/ssl/%s"
	}
	if c.Nginx.CertFile == "" {
		c.Nginx.CertFile = "fullchain.pem"
	}
	if c.Nginx.KeyFile == "" {
		c.Nginx.KeyFile = "privkey.pem"
	}
	// YAML preserves absent as nil and reload: [] as a non-nil empty slice.
	// The latter is an explicit, documented "write files but do not reload"
	// choice; only an absent field receives the safe default.
	if c.Nginx.Reload == nil {
		// Default rather than "no reload": forgetting to reload is how a renewed
		// certificate sits on disk while nginx keeps serving the old one until the
		// next restart -- and the process cannot see that. An operator who manages
		// reloads elsewhere sets reload: [] explicitly.
		c.Nginx.Reload = []string{"systemctl", "reload", "nginx"}
	}
	if c.Nginx.CertFile == c.Nginx.KeyFile {
		return fmt.Errorf("nginx.certFile and nginx.keyFile must differ, got %q for both",
			c.Nginx.CertFile)
	}
	if !strings.Contains(c.Nginx.DirTemplate, "%s") {
		return fmt.Errorf("nginx.dirTemplate %q must contain %%s (the certificate name); "+
			"without it every certificate would share one directory and overwrite the others",
			c.Nginx.DirTemplate)
	}
	for i := range c.Nginx.Reload {
		if strings.TrimSpace(c.Nginx.Reload[i]) == "" {
			return fmt.Errorf("nginx.reload[%d] is empty; reload is an argv slice, not a shell string",
				i)
		}
	}
	return nil
}

// normalizeSubsections delegates to the typed sections that already own their own
// rules (backup, desired state, onboarding, probe, fallback).
func (c *Config) normalizeSubsections() error {
	if err := c.StateBackup.normalize(); err != nil {
		return err
	}
	if err := c.DesiredState.normalize(len(c.Certificates) > 0); err != nil {
		return err
	}
	if err := c.Onboarding.normalize(); err != nil {
		return err
	}
	if err := c.Probe.normalize(); err != nil {
		return err
	}
	return c.Fallback.normalize()
}

// normalizeCertificatesBlock checks the certificate list and the one cross-cutting
// rule that needs both the list and a profile default filled in above (the probe floor).
func (c *Config) normalizeCertificatesBlock() error {
	// Both static and observe converge on certificates, so a non-empty list is a
	// hard requirement. In enforce mode certificates must be empty (rejected
	// above); the document is the only source.
	if c.DesiredState.Mode != ModeEnforce && len(c.Certificates) == 0 {
		return fmt.Errorf("at least one certificate is required "+
			"(desiredState.mode=%q still converges on this list; "+
			"set desiredState.mode=%q to take the whole list from the desired-state document instead)",
			c.DesiredState.Mode, ModeEnforce)
	}

	if err := NormalizeCertificates(c.Certificates); err != nil {
		return err
	}

	// probe.minValidFor must be satisfiable by the shortest profile in use.
	//
	// probe.Verify fails every probe whose remaining validity is below this floor, and the runner
	// turns that into wecert_certificate_probe_match = 0 -- so an unsatisfiable floor pins the
	// metric at zero forever and fires the critical "not serving the deployed certificate" alert
	// with a diagnosis that blames the rebind or SNI. The file already rejects the analogous
	// "renewBefore >= validity" for the same reason: cheap to check, and the failure it prevents
	// looks like something else entirely.
	//
	// In enforce mode this loop sees an empty list -- the document is the only source of
	// certificates there -- so the same check runs again where the document is resolved, which is
	// the only place the two can meet. See CheckProbeFloor.
	return CheckProbeFloor(c.Probe.MinValidDur, c.Certificates)
}

// CheckProbeFloor rejects a probe.minValidFor that no profile in use can satisfy.
//
// probe.Verify fails every probe whose remaining validity is below this floor, and the runner turns
// that into wecert_certificate_probe_match = 0 -- so an unsatisfiable floor pins the metric at zero
// forever and fires the critical "not serving the deployed certificate" alert with a diagnosis that
// blames the rebind or SNI.
//
// It is exported because the certificates are not always in the config file: in enforce mode
// c.Certificates must be empty, so the only place the floor and the certificates can meet is where
// the document is resolved. Config.normalize calls it for the static and observe modes; the
// reconciler calls it on every resolved pass and reports the mismatch, because a document may
// change between passes and failing the pass there would stop renewals over a probe setting.
func CheckProbeFloor(minValid time.Duration, certs []Certificate) error {
	if minValid <= 0 {
		return nil
	}
	for i := range certs {
		cert := &certs[i]
		validity, ok := profileValidity[cert.Profile]
		if !ok {
			continue
		}
		if minValid >= validity {
			return fmt.Errorf(
				"probe.minValidFor %s is not shorter than certificate %q's %s profile validity %s, "+
					"so every probe of it would fail while the certificate is still perfectly valid "+
					"(wecert_certificate_probe_match stays 0 and the alert blames the rebind); "+
					"use less than %s",
				minValid, cert.Name, cert.Profile, validity, validity)
		}
	}
	return nil
}

func (w *Webhook) normalize() error {
	// Checked before the listen-address branch below: NotifyURL is independent of the
	// trigger endpoint and may be used alone, so it is validated on every path that
	// carries it.
	if w.NotifyURL != "" {
		u, err := url.Parse(w.NotifyURL)
		if err != nil {
			return fmt.Errorf("webhook.notifyURL: %w", err)
		}
		// A URL without a host or with another scheme would be POSTed to by the notifier
		// and fail there, one renewal at a time, with the cause far from the config line.
		if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("webhook.notifyURL must be an http or https URL with a host, got %q", w.NotifyURL)
		}
	}

	// Checked before the listen-address branch below: NotifySecret is about the
	// outbound event target, which is independent of the trigger endpoint.
	if w.NotifySecret != "" {
		if w.NotifyURL == "" {
			return fmt.Errorf("webhook.notifySecret is set but webhook.notifyURL is empty: " +
				"there is no outgoing event for the signature to cover")
		}
		if len(w.NotifySecret) < WebhookNotifySecretMinLen {
			return fmt.Errorf("webhook.notifySecret is too short (%d characters, minimum %d): "+
				"a key this short can be recovered from a single signed event, so it would not "+
				"prove the notification came from wecert",
				len(w.NotifySecret), WebhookNotifySecretMinLen)
		}
	}

	// An empty Listen means disabled, in which case Token is not needed either.
	if w.Listen == "" {
		if w.Token != "" {
			return fmt.Errorf("webhook.token is set but webhook.listen is empty: " +
				"with no listen address there is no endpoint for the token to guard")
		}
		if w.NotifyURL != "" {
			// NotifyURL is independent of the listen endpoint and may be used alone.
			return nil
		}
		return nil
	}

	// Same rule as metrics.listen: a malformed address must fail at load time, not at the
	// first bind.
	if _, _, err := net.SplitHostPort(w.Listen); err != nil {
		return fmt.Errorf("webhook.listen must be a host:port address, got %q: %w", w.Listen, err)
	}

	if w.Token == "" {
		return fmt.Errorf("webhook.listen is set but webhook.token is missing: " +
			"this endpoint triggers real issuance and consumes rate-limit quota, so it must be authenticated")
	}
	if len(w.Token) < WebhookTokenMinLen {
		return fmt.Errorf("webhook.token is too short (%d characters, minimum %d): "+
			"this endpoint can trigger real issuance, so a weak token is no better than none",
			len(w.Token), WebhookTokenMinLen)
	}
	if w.NotifyFormat == "" {
		w.NotifyFormat = NotifyFormatGeneric
	}
	switch w.NotifyFormat {
	case NotifyFormatGeneric, NotifyFormatPagerDuty, NotifyFormatFeishu,
		NotifyFormatWeCom, NotifyFormatDingTalk, NotifyFormatSlack:
	default:
		return fmt.Errorf("webhook.notifyFormat must be %q, %q, %q, %q, %q or %q, got %q",
			NotifyFormatGeneric, NotifyFormatPagerDuty, NotifyFormatFeishu,
			NotifyFormatWeCom, NotifyFormatDingTalk, NotifyFormatSlack, w.NotifyFormat)
	}
	if w.NotifyFormat == NotifyFormatPagerDuty && w.PagerDuty.RoutingKey == "" &&
		w.PagerDuty.RoutingKeyFile == "" {
		return fmt.Errorf("webhook.notifyFormat=\"%s\" requires webhook.pagerduty.routingKey or "+
			"webhook.pagerduty.routingKeyFile (the Events API v2 integration key)",
			NotifyFormatPagerDuty)
	}
	if w.AdminToken != "" {
		if len(w.AdminToken) < WebhookAdminTokenMinLen {
			return fmt.Errorf("webhook.adminToken is too short (%d characters, minimum %d): "+
				"it can restore state.db, so treat it like a root password",
				len(w.AdminToken), WebhookAdminTokenMinLen)
		}
		if w.AdminToken == w.Token {
			return fmt.Errorf("webhook.adminToken must differ from webhook.token: the read-only " +
				"token is what a status poller holds, and the admin token can restore a snapshot")
		}
	}
	return nil
}

// ValidProfile reports whether name is a certificate profile this build knows.
//
// Exported so the callers that produce a profile BEFORE a Certificate exists -- the declaration
// parser in internal/onboarding, which reads "profile=tlsserver" out of a TXT record -- can reject
// a bad value where it is written, instead of letting it reach NormalizeCertificates at document
// write time. That path made one typo in one TXT record fail Commit for EVERY certificate, every
// round, until a human edited DNS.
