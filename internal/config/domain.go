// Package config defines wecert's declarative desired state (the spec).
//
// Design principle: the YAML says only "what I want" and carries no runtime
// state at all. Runtime state (order URL, ARI window, Tencent Cloud CertId and
// so on) always goes into SQLite, because losing it directly causes duplicate
// orders and runs into Let's Encrypt rate limits.
package config

import (
	"fmt"
	"golang.org/x/net/publicsuffix"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Split out so one concern lives in one file. Same package.

func ValidProfile(name string) bool {
	_, ok := profileMaxNames[name]
	return ok
}

// ValidKeyType reports whether kt is a key type this build can generate.
func ValidKeyType(kt string) bool {
	switch kt {
	case KeyTypeECDSAP256, KeyTypeECDSAP384, KeyTypeRSA2048, KeyTypeRSA4096:
		return true
	default:
		return false
	}
}

func (c *Certificate) normalize(seen map[string]bool) error {
	if c.Name == "" {
		return fmt.Errorf("certificates[].name is required")
	}
	if seen[c.Name] {
		return fmt.Errorf("certificate name %q is duplicated", c.Name)
	}
	seen[c.Name] = true

	if c.Profile == "" {
		c.Profile = ProfileClassic
	}
	maxNames, ok := profileMaxNames[c.Profile]
	if !ok {
		return fmt.Errorf("certificate %q: unknown profile %q (want %s/%s/%s)",
			c.Name, c.Profile, ProfileClassic, ProfileTLSServer, ProfileShortLived)
	}

	if c.KeyType == "" {
		c.KeyType = KeyTypeECDSAP256
	}
	if !ValidKeyType(c.KeyType) {
		return fmt.Errorf("certificate %q: unknown keyType %q", c.Name, c.KeyType)
	}

	if len(c.Domains) == 0 {
		return fmt.Errorf("certificate %q: domains is empty", c.Name)
	}

	// Normalize the domains first (lowercase, dedupe, validate), then check the cap.
	//
	// The order matters: on certificates with many SANs the domains list is usually
	// pasted in wholesale from elsewhere, so duplicates and mixed case are the
	// norm. Checking the cap first would count a 100-domain config with 1
	// accidental duplicate as 101 and reject it, even though it is legal.
	normalized, err := normalizeDomains(c.Domains)
	if err != nil {
		return fmt.Errorf("certificate %q: %w", c.Name, err)
	}
	c.Domains = normalized

	if len(c.Domains) > maxNames {
		return fmt.Errorf(
			"certificate %q: %d domains exceeds the %s profile's max of %d identifiers; "+
				"split it into smaller certificates (and remember every name fails together)",
			c.Name, len(c.Domains), c.Profile, maxNames)
	}

	c.RenewBeforeDur, err = parseDuration(c.RenewBefore, profileRenewBefore[c.Profile],
		fmt.Sprintf("certificate %q renewBefore", c.Name))
	if err != nil {
		return err
	}

	// renewBefore must be shorter than the certificate's own lifetime.
	//
	// The renewal time is notAfter - renewBefore, so a value at or beyond the validity
	// puts that instant in the past from the moment the certificate is issued: every pass
	// then decides "renew now". ARI normally masks this -- it takes precedence, and its
	// window is always inside the lifetime -- so the mistake only surfaces when ARI is
	// unavailable, and then it re-orders the same identifier set every hour until the
	// account's 5-per-exact-set/7-day quota is gone.
	//
	// Rejecting it is cheap and the failure it prevents is a week-long stall, which is the
	// same trade the domain validation above makes.
	if v, ok := profileValidity[c.Profile]; ok && c.RenewBeforeDur >= v {
		return fmt.Errorf(
			"certificate %q: renewBefore %s is not shorter than the %s profile's %s validity, "+
				"so renewal would be due the moment the certificate is issued (and would re-order every pass "+
				"whenever ARI is unavailable); use less than %s",
			c.Name, c.RenewBeforeDur, c.Profile, v, v)
	}
	if c.FailureFallback != nil {
		if err := c.FailureFallback.normalize(); err != nil {
			return fmt.Errorf("certificate %q failureFallback: %w", c.Name, err)
		}
	}
	if c.Export != nil {
		c.Export.LocalDir = strings.TrimSpace(c.Export.LocalDir)
		if c.Export.LocalDir == "" && len(c.Export.RemoteTargets) == 0 {
			return fmt.Errorf("certificate %q export needs localDir and/or remoteTargets", c.Name)
		}
		for i := range c.Export.RemoteTargets {
			if err := c.Export.RemoteTargets[i].normalize(i); err != nil {
				return fmt.Errorf("certificate %q export: %w", c.Name, err)
			}
		}
	}
	return nil
}

// normalizeDomains trims whitespace, lowercases, dedupes as a set, and
// validates each entry.
//
// Keeping the original config order is deliberate: the classic profile promotes
// the first dNSName to CN, so changing the order changes the certificate's
// Subject CN with it.
func normalizeDomains(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))

	for _, raw := range in {
		d := strings.ToLower(strings.TrimSpace(raw))
		if err := validateDomain(d); err != nil {
			return nil, err
		}
		if seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out, nil
}

// DomainKey returns the fingerprint of the domain set this certificate wants.
func (c *Certificate) DomainKey() string { return DomainKey(c.Domains) }

// DomainKey compresses a set of domains into a string independent of order,
// case and duplicates.
//
// It exists to compare "the set the config wants" against "the SANs actually in
// the certificate": comparing []string directly is disturbed by order and case,
// neither of which has any semantic effect on a certificate.
func DomainKey(domains []string) string {
	seen := make(map[string]bool, len(domains))
	cp := make([]string, 0, len(domains))
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		cp = append(cp, d)
	}
	sort.Strings(cp)
	return strings.Join(cp, ",")
}

// DiffDomains returns what want has and have lacks (missing), and what have has
// and want lacks (extra).
//
// Both directions matter: checking only missing would overlook "a domain was
// deleted from the config", where the extra SAN in the certificate is just as
// much a deviation that needs converging.
func DiffDomains(want, have []string) (missing, extra []string) {
	inWant := make(map[string]bool, len(want))
	inHave := make(map[string]bool, len(have))
	for _, d := range want {
		inWant[strings.ToLower(strings.TrimSpace(d))] = true
	}
	for _, d := range have {
		inHave[strings.ToLower(strings.TrimSpace(d))] = true
	}
	for d := range inWant {
		if !inHave[d] {
			missing = append(missing, d)
		}
	}
	for d := range inHave {
		if !inWant[d] {
			extra = append(extra, d)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return missing, extra
}

// validateDomain blocks several forms that are known to be rejected by the CA,
// or whose coverage is easily misunderstood.
//
// Why not let the CA report the error: every rejected order consumes order
// quota, and on a certificate with many SANs one typo costs a full re-issue.
// Blocking locally is cheaper.
// ValidateDomain validates one domain, allowing a single wildcard label on the
// far left.
//
// It is exported so desired-state sources reuse the same rules: if a source
// accepted a name wecert rejects, convergence would get stuck on an error that
// can never be fixed, with the reported failure far from the real cause.
func ValidateDomain(d string) error { return validateDomain(d) }

// NormalizeCertificates validates and normalizes a set of certificates: fills
// in defaults, dedupes names, validates domains and count caps.
//
// Both the static config and the desired-state document come through this one
// entry point, so the two paths cannot differ in strictness — that is where
// bizarre "passes in the document, fails in the config" gaps come from.
//
// The one check it cannot host is spec.checkNameStability, which needs the grouping
// package; that imports this one, so hosting it here would be a cycle. It is named here
// so the claim above stays honest instead of quietly becoming false.
func NormalizeCertificates(certs []Certificate) error {
	seen := make(map[string]bool, len(certs))
	byDomainSet := make(map[string]string, len(certs))
	for i := range certs {
		if err := certs[i].normalize(seen); err != nil {
			return err
		}

		// Reject two certificates that ask for the same identifier set AND the same key
		// type under different names.
		//
		// Both count against the same "5 certificates per exact set of identifiers /
		// 7 days" bucket and both spend "Certificates per Registered Domain", and they
		// cover the same names with the same key algorithm, so the second one buys
		// nothing while halving the number of attempts left for the first. This is
		// exactly the cheap local rejection the domain validation above exists for.
		//
		// The key type is part of the dedupe key because the same names with a DIFFERENT
		// algorithm are a legitimate dual-certificate setup (an RSA certificate beside an
		// ECDSA one, so clients without ECDSA still get served): those are distinct
		// certificates with distinct keys, not duplicates.
		//
		// The desired-state path additionally requires a certificate name to be derived
		// from its registered domain (spec.checkNameStability); that rule lives there
		// because it needs the grouping package, which imports this one. The overlap
		// check needs nothing beyond DomainKey and the key type, so it protects both
		// entry points -- which is what the "same entry point, same strictness" claim
		// requires.
		key := certs[i].DomainKey() + "|" + certs[i].KeyType
		if prev, dup := byDomainSet[key]; dup {
			return fmt.Errorf(
				"certificates %q and %q ask for the same identifier set (%s) with the same keyType: "+
					"they would share the 5-per-exact-set/7-days quota and cover the same names, so one of "+
					"them can only waste it (an RSA+ECDSA pair over the same names is fine -- that is "+
					"exactly what the keyType in this check is for)",
				prev, certs[i].Name, certs[i].DomainKey())
		}
		byDomainSet[key] = certs[i].Name
	}
	return nil
}

func validateDomain(d string) error {
	if d == "" {
		return fmt.Errorf("empty domain")
	}
	if strings.HasSuffix(d, ".") {
		return fmt.Errorf("domain %q has a trailing dot", d)
	}
	if len(d) > 253 {
		return fmt.Errorf("domain %q is longer than 253 characters", d)
	}
	if strings.ContainsAny(d, " \t\r\n/") {
		return fmt.Errorf("domain %q contains whitespace or a slash", d)
	}

	// An IP literal cannot be validated with DNS-01, and it does not fail on its own: lego promotes
	// a literal to an RFC 8738 "ip" identifier, the CA then offers only tls-alpn-01 and http-01 for
	// it, and pickDNS01 finds no dns-01 challenge -- so the WHOLE certificate stops issuing, every
	// pass, with an error that names the challenge type rather than the domain that caused it.
	// Rejecting it here turns "this certificate never works" into "this line of the document is
	// wrong". (IPv6 literals are not even expressible as a hostname label, and a wildcard over an
	// address is nonsense, so the base name is what is checked.)
	if net.ParseIP(strings.TrimPrefix(d, "*.")) != nil {
		return fmt.Errorf("domain %q is an IP address: Let's Encrypt issues certificates for DNS "+
			"names, and this program validates with DNS-01, which an address identifier cannot "+
			"answer -- use a name that resolves to it instead", d)
	}
	// A single label, or a public suffix ("co.uk"), cannot be issued either: the CA needs a name
	// under a registrable domain it can validate, and an identifier with nothing above it is
	// exactly the "internal name" the CA/Browser Forum baseline requirements forbid a public CA to
	// sign. The PSL is consulted here rather than through internal/group because group imports this
	// package (it validates through ValidateDomain), so the dependency only runs one way.
	if base := strings.TrimPrefix(d, "*."); base != "" {
		if suffix, _ := publicsuffix.PublicSuffix(base); suffix == base {
			return fmt.Errorf("domain %q IS a public suffix (or has no suffix above it at all), so no "+
				"certificate authority can validate it; use a name under it, e.g. www.%s", d, base)
		}
	}

	// Check label by label. Empty labels (a..example.com), over-long labels and
	// illegal characters are all rejected by the CA.
	for _, label := range strings.Split(d, ".") {
		if label == "*" {
			// The wildcard label itself is legal; its position is checked separately below.
			continue
		}
		if label == "" {
			return fmt.Errorf("domain %q has an empty label", d)
		}
		if len(label) > 63 {
			return fmt.Errorf("domain %q: label %q exceeds 63 characters", d, label)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("domain %q: label %q must not start or end with a hyphen", d, label)
		}
		for i := 0; i < len(label); i++ {
			ch := label[i]
			if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' {
				continue
			}
			return fmt.Errorf("domain %q: label %q contains an invalid character %q", d, label, string(ch))
		}
	}

	if strings.Contains(d, "*") {
		// LE allows only a single wildcard label, at the far left.
		if !strings.HasPrefix(d, "*.") {
			return fmt.Errorf("domain %q: wildcard must be the leftmost label (e.g. *.example.com)", d)
		}
		if strings.Contains(d[2:], "*") {
			return fmt.Errorf("domain %q: *.*.example.com is not allowed by Let's Encrypt", d)
		}
	}
	return nil
}

func parseDuration(s string, def time.Duration, field string) (time.Duration, error) {
	if s == "" {
		if def == 0 {
			return 0, fmt.Errorf("%s is required", field)
		}
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%s: %w (note: there is no day unit; use hours, e.g. 720h for 30 days)", field, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive, got %s", field, s)
	}
	return d, nil
}

// normalizeRecursiveNameservers accepts IP literals with an optional UDP/TCP
// port. Resolver hostnames are deliberately rejected: resolving the resolver
// name through the system resolver would reintroduce the trust ambiguity this
// setting exists to remove.
func normalizeRecursiveNameservers(in []string) ([]string, error) {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		v := strings.TrimSpace(raw)
		if v == "" {
			return nil, fmt.Errorf("dns.recursiveNameservers contains an empty resolver")
		}
		host, port, err := splitResolverAddress(v)
		if err != nil {
			return nil, fmt.Errorf("dns.recursiveNameservers entry %q: %w", raw, err)
		}
		if net.ParseIP(host) == nil {
			return nil, fmt.Errorf("dns.recursiveNameservers entry %q must use an IP address, not a hostname", raw)
		}
		if port == "" {
			port = "53"
		}
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return nil, fmt.Errorf("dns.recursiveNameservers entry %q has an invalid port", raw)
		}
		addr := net.JoinHostPort(host, port)
		if !seen[addr] {
			seen[addr] = true
			out = append(out, addr)
		}
	}
	return out, nil
}

func splitResolverAddress(v string) (host, port string, err error) {
	if ip := net.ParseIP(v); ip != nil {
		return v, "", nil
	}
	host, port, err = net.SplitHostPort(v)
	if err == nil {
		if host == "" || port == "" {
			return "", "", fmt.Errorf("host and port are both required when a port is specified")
		}
		return host, port, nil
	}
	if strings.Contains(v, ":") {
		return "", "", fmt.Errorf("must be an IP literal optionally followed by a numeric port")
	}
	return v, "", nil
}

// profileValidity is each profile's nominal certificate lifetime as Let's Encrypt
// issues it. It is not used to decide anything -- ARI and renewBefore own that -- only
// to scale the local "approaching expiry" warning below.
func ExpiryWarningThreshold(profile string) time.Duration {
	v, ok := profileValidity[profile]
	if !ok {
		v = profileValidity[ProfileClassic]
	}
	return v / 4
}

// DaysUntil is the whole number of days left before notAfter, rounded **up**.
//
// Rounded up, because truncation makes "23 hours left" read as 0 days, and 0 days is a
// meaningless thing to report for a certificate that is still valid -- a consumer that
// treats 0 as expired reads a healthy certificate as down. probe.DaysLeft uses the same
// rule; keep the two in step.
func DaysUntil(notAfter, now time.Time) int {
	left := notAfter.Sub(now)
	if left <= 0 {
		return 0
	}
	return int((left + 24*time.Hour - 1) / (24 * time.Hour))
}

// ── secrets from files ──────────────────────────────────────────────────────────────
//
// A credential in config.yaml is a credential in every backup, every paste into a chat window and
// every `cat` while debugging. These three fields let an operator keep them out of the file
// entirely, which is the difference between "rotate the token" and "rotate the token and also
// rewrite every copy of the config that ever existed".
//
// The shape follows systemd's LoadCredential, which is what the shipped unit can use:
//
//	# deploy/systemd/wecert.service.d/credentials.conf
//	[Service]
//	LoadCredential=dnspod-token:/etc/wecert/dnspod.token
//
// systemd then exposes the file at $CREDENTIALS_DIRECTORY/dnspod-token, and the config says
// `loginTokenFile: ${CREDENTIALS_DIRECTORY}/dnspod-token`. That is why the path is
// environment-expanded: CREDENTIALS_DIRECTORY only exists once systemd has started the unit, so a
// literal path cannot express it.

// resolveSecretFiles fills in the *_file variants, and the environment fallbacks.
//
// Called from Load, before validation, so a typo'd path is reported while the operator is looking
// at it rather than after an order has been placed and a challenge has failed -- a rate-limited
// failure is much more expensive than a config error.
//
// Every configured path is read, even one the chosen provider does not use. A config that names a
// file which is not there is wrong whether or not today's provider reads it, and failing now is
// cheaper than failing on the day the provider changes.
func validateContactEmail(email string) error {
	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 {
		return fmt.Errorf("acme.email %q is not a usable contact address: it must look like "+
			"user@domain, and it should be a mailbox you can read -- it is where a CA sends expiry "+
			"and revocation notices", email)
	}
	domain := strings.ToLower(strings.TrimSuffix(email[at+1:], "."))

	// The domain and every parent of it: mail to anything under a reserved domain goes nowhere, so
	// `ops@sub.example.net` is the same mistake as `ops@example.net` and a CA refuses it the same way.
	for suffix := domain; suffix != ""; {
		if reservedContactDomains[suffix] {
			return fmt.Errorf("acme.email is %q, and %s is a reserved documentation domain: Let's "+
				"Encrypt refuses it as a contact address (\"contact email has forbidden domain\") when "+
				"it registers the account, so nothing is issued at all. Set acme.email to a mailbox you "+
				"control", email, suffix)
		}
		dot := strings.IndexByte(suffix, '.')
		if dot < 0 {
			// A single label ("localhost", or a bare name): the whole thing is the last label, so the
			// special-use check below has to see it too.
			if reservedContactTLDs[suffix] {
				return fmt.Errorf("acme.email is %q, and %q is a reserved special-use name: a CA refuses "+
					"it as a contact address, so nothing is issued at all. Set acme.email to a mailbox "+
					"you control", email, suffix)
			}
			break
		}
		suffix = suffix[dot+1:]
		if reservedContactTLDs[suffix] {
			return fmt.Errorf("acme.email is %q, and .%s is a reserved special-use TLD: a CA refuses it "+
				"as a contact address, so nothing is issued at all. Set acme.email to a mailbox you "+
				"control", email, suffix)
		}
	}
	return nil
}

// ACME is the ACME account and directory configuration.
