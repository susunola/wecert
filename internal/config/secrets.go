package config

import (
	"fmt"
	"os"
	"strings"
)

// ExpiryWarningThreshold is how close to expiry a certificate has to get before the
// daemon logs a warning about it.
//
// Scaled to the profile rather than fixed. A fixed 21 days is most of a `shortlived`
// certificate's 160-hour life, so that profile warned from the moment it was issued --
// on every pass, for its whole life, which is exactly the kind of alarm that trains
// people to ignore logs. A quarter of the validity is early enough to act on and late
// enough to mean something. The metrics remain the primary expiry signal; this is a
// secondary log line.
func (c *Config) resolveSecretFiles() ([]string, error) {
	var warns []string
	resolve := func(field, value, file string, envs []string, target *string) error {
		if value != "" && file != "" {
			return fmt.Errorf("%s and its file variant are both set; keep one of them so it is "+
				"unambiguous which one is in use", field)
		}
		if value != "" {
			return nil
		}
		if file != "" {
			// The file wins over the environment, and says so: two live sources for one
			// credential means a rotation of either one can silently not take effect.
			// Only the variable NAME is printed, never its value.
			for _, env := range envs {
				if strings.TrimSpace(os.Getenv(env)) != "" {
					warns = append(warns, fmt.Sprintf("%s is set both in %s and in $%s; the file is used "+
						"and the environment value is ignored -- remove one of them so it is unambiguous "+
						"which credential is in use", field, file, env))
				}
			}
			// Environment-expanded so ${CREDENTIALS_DIRECTORY} works: systemd sets it only after
			// the unit starts, so the path cannot be written literally in the file.
			path := os.ExpandEnv(file)
			raw, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read %s from %s: %w (the path is environment-expanded, so "+
					"${CREDENTIALS_DIRECTORY} is only set when systemd runs this)", field, path, err)
			}
			if fi, statErr := os.Stat(path); statErr == nil {
				warns = append(warns, secretFilePermWarnings(field, path, fi.Mode().Perm())...)
			}
			secret := strings.TrimSpace(string(raw))
			if secret == "" {
				return fmt.Errorf("%s file %s is empty; a blank credential would be sent to the "+
					"provider as an empty string and rejected there, far from the cause", field, path)
			}
			*target = secret
			return nil
		}
		for _, env := range envs {
			if v := strings.TrimSpace(os.Getenv(env)); v != "" {
				*target = v
				return nil
			}
		}
		return nil
	}

	if err := resolve("dns.loginToken", c.DNS.LoginToken, c.DNS.LoginTokenFile,
		[]string{EnvDNSPodLoginToken}, &c.DNS.LoginToken); err != nil {
		return warns, err
	}
	if err := resolve("acme.eab.hmac", c.ACME.EAB.HMAC, c.ACME.EAB.HMACFile,
		[]string{"WECERT_ACME_EAB_HMAC"}, &c.ACME.EAB.HMAC); err != nil {
		return warns, err
	}
	if c.StateEncryption.KeyFile != "" {
		path := os.ExpandEnv(c.StateEncryption.KeyFile)
		raw, err := os.ReadFile(path)
		if err != nil {
			return warns, fmt.Errorf("read stateEncryption.keyFile %s: %w", path, err)
		}
		c.StateEncryption.Key = strings.TrimSpace(string(raw))
		if c.StateEncryption.Key == "" {
			return warns, fmt.Errorf("stateEncryption.keyFile %s is empty", path)
		}
	}

	// The two provider blocks below are resolved only when their provider is the selected one.
	//
	// Otherwise the ambient environment would decide: a host that exports CLOUDFLARE_DNS_API_TOKEN
	// for some other tool, or AWS_ACCESS_KEY_ID for the AWS CLI, would have a field filled in on a
	// config that selects dnspod -- and normalizeDNS rejects a provider block that belongs to
	// another provider, so an unrelated variable in the environment would turn a working config
	// into a load error. Which provider is in use comes from the file, so only the file can put a
	// value in these fields.
	if c.DNS.Provider == DNSProviderCloudflare {
		if err := resolve("dns.cloudflare.apiToken", c.DNS.Cloudflare.APIToken,
			c.DNS.Cloudflare.APITokenFile,
			[]string{EnvCloudflareAPIToken, EnvCloudflareAPITokenAlt},
			&c.DNS.Cloudflare.APIToken); err != nil {
			return warns, err
		}
	}
	if c.DNS.Provider == DNSProviderRoute53 {
		// Region has no file variant -- it is not a secret -- but it has the two environment
		// fallbacks the AWS SDK itself reads, so a deployment that already sets AWS_REGION does not
		// have to repeat it here.
		if c.DNS.Route53.Region == "" {
			for _, env := range []string{EnvAWSRegion, EnvAWSDefaultRegion} {
				if v := strings.TrimSpace(os.Getenv(env)); v != "" {
					c.DNS.Route53.Region = v
					break
				}
			}
		}
		// The static secret key has a file variant for the same reason as loginToken. There is no
		// environment fallback here on purpose: AWS_SECRET_ACCESS_KEY belongs to the SDK's default
		// chain, which is used when no static pair is configured, and copying it into the config
		// field would instead build a static provider out of half of a pair.
		if err := resolve("dns.route53.secretAccessKey", c.DNS.Route53.SecretAccessKey,
			c.DNS.Route53.SecretAccessKeyFile, nil, &c.DNS.Route53.SecretAccessKey); err != nil {
			return warns, err
		}
		if err := resolve("dns.route53.sessionToken", c.DNS.Route53.SessionToken,
			c.DNS.Route53.SessionTokenFile, nil, &c.DNS.Route53.SessionToken); err != nil {
			return warns, err
		}
	}

	if c.Webhook.NotifyFormat == NotifyFormatJira {
		if err := resolve("webhook.jira.apiToken", c.Webhook.Jira.APIToken,
			c.Webhook.Jira.APITokenFile, nil, &c.Webhook.Jira.APIToken); err != nil {
			return warns, err
		}
	}
	if c.Webhook.NotifyFormat == NotifyFormatPagerDuty {
		if err := resolve("webhook.pagerduty.routingKey", c.Webhook.PagerDuty.RoutingKey,
			c.Webhook.PagerDuty.RoutingKeyFile, nil, &c.Webhook.PagerDuty.RoutingKey); err != nil {
			return warns, err
		}
	}
	if err := resolve("tencent.secretId", c.Tencent.SecretID, c.Tencent.SecretIDFile,
		[]string{"TENCENTCLOUD_SECRET_ID"}, &c.Tencent.SecretID); err != nil {
		return warns, err
	}
	if err := resolve("tencent.secretKey", c.Tencent.SecretKey, c.Tencent.SecretKeyFile,
		[]string{"TENCENTCLOUD_SECRET_KEY"}, &c.Tencent.SecretKey); err != nil {
		return warns, err
	}

	// The webhook secrets have no environment fallback: they guard a local endpoint and
	// sign outbound events, so a file variant is the whole story.
	if err := resolve("webhook.token", c.Webhook.Token, c.Webhook.TokenFile,
		nil, &c.Webhook.Token); err != nil {
		return warns, err
	}
	if err := resolve("webhook.notifySecret", c.Webhook.NotifySecret, c.Webhook.NotifySecretFile,
		nil, &c.Webhook.NotifySecret); err != nil {
		return warns, err
	}
	return warns, nil
}

// secretFilePermWarnings warns when a *_file credential path is readable by group or
// other. Pure like configPermWarnings so the wording is testable without capturing
// stderr. The file's own mode is the check: the config may live anywhere, and a
// systemd LoadCredential directory is already 0400. A warning rather than a refusal,
// matching configPermWarnings: refusing would push operators toward copying the secret
// back into config.yaml.
func secretFilePermWarnings(field, path string, perm os.FileMode) []string {
	if perm&0o077 == 0 {
		return nil
	}
	return []string{fmt.Sprintf(
		"the credential file for %s (%s) is readable by group or other (%04o). "+
			"A secret in a wide file is in every backup and every archive of that path; "+
			"chmod 0600 it (a systemd LoadCredential path is usually already 0400)",
		field, path, perm)}
}

// EnvDNSPodLoginToken is the environment variable read when neither dns.loginToken nor
// dns.loginTokenFile is set. It exists so a container or a systemd EnvironmentFile can supply the
// token without touching the config at all.
const EnvDNSPodLoginToken = "DNSPOD_LOGIN_TOKEN"

// EnvCloudflareAPIToken is the variable lego's cloudflare provider documents for the scoped API
// token, and EnvCloudflareAPITokenAlt the short alias it also accepts. Either can supply
// dns.cloudflare.apiToken when neither the field nor its file variant is set.
const (
	EnvCloudflareAPIToken    = "CLOUDFLARE_DNS_API_TOKEN"
	EnvCloudflareAPITokenAlt = "CF_DNS_API_TOKEN"
)

// EnvAWSRegion and EnvAWSDefaultRegion are the two variables the AWS SDK reads for a region; they
// stand in for dns.route53.region when it is empty, so a config that already sets one works here.
const (
	EnvAWSRegion        = "AWS_REGION"
	EnvAWSDefaultRegion = "AWS_DEFAULT_REGION"
)
