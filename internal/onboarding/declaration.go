package onboarding

import (
	"fmt"
	"strings"

	"github.com/susunola/wecert/internal/group"

	"github.com/susunola/wecert/internal/config"
)

// DeclarationPrefix is the record-name prefix for a declaration.
//
// Why make declarations DNS records instead of letting wecert enumerate DNS
// records and infer intent: the DNS zone is already this system's root of trust
// -- whoever can write the zone can already do DNS-01 validation for any name in
// it and obtain a certificate from any CA. Keeping declarations here introduces
// no new trust boundary; it only makes an existing capability explicit.
//
// Conversely, "any DNS record means issue" is explicitly not done: the zone holds
// MX/TXT/SPF and all kinds of verification records, and a DNS record is not a
// request for a certificate. Authorization must be an explicit act.
const DeclarationPrefix = "_wecert."

// DeclarationVersion is the declaration format version, written as v=wecert1.
const DeclarationVersion = "wecert1"

// Declaration is the parsed result of one _wecert TXT declaration.
type Declaration struct {
	// Hostname is the name declared to need a certificate: the record name with
	// the _wecert. prefix stripped off.
	Hostname string

	// Wildcard means *.<Hostname> is declared as well.
	//
	// A wildcard must be declared explicitly: adding *.example.com means the
	// certificate can handshake for any subdomain, which is privilege expansion
	// and must not be decided on a human's behalf by grouping logic.
	Wildcard bool

	// The next three are optional overrides; empty means the onboarding default.
	Profile string
	KeyType string
	Deploy  *bool

	// Zone and Record are for reporting and troubleshooting only.
	Zone   string
	Record string
}

// Names returns every name this declaration contributes, including wildcard
// expansion.
func (d *Declaration) Names() []string {
	out := make([]string, 0, 2)
	out = append(out, d.Hostname)
	if d.Wildcard {
		out = append(out, "*."+d.Hostname)
	}
	return out
}

// ParseDeclaration parses one _wecert.* TXT record into a declaration.
//
// Unknown keys are always an error rather than ignored. The reason is plain: if a
// typo like `wildard=1` were silently ignored, the result would be "declared a
// wildcard but it never took effect" while the human believes it did -- a silent
// divergence like that costs far more than a clear error.
func ParseDeclaration(zone, record string, values []string) (*Declaration, error) {
	full := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(record)), ".")
	if !strings.HasPrefix(full, DeclarationPrefix) {
		return nil, fmt.Errorf("record %q does not start with %q", record, DeclarationPrefix)
	}

	host, err := group.Normalize(strings.TrimPrefix(full, DeclarationPrefix))
	if err != nil {
		return nil, fmt.Errorf("record %q: %w", record, err)
	}
	if group.IsWildcard(host) {
		return nil, fmt.Errorf("record %q: the name after %q must not itself be a wildcard; use wildcard=1 instead",
			record, DeclarationPrefix)
	}

	d := &Declaration{Hostname: host, Zone: zone, Record: full}
	given := make(map[string]string)

	for _, v := range values {
		for _, field := range splitFields(v) {
			key, val, hasValue := strings.Cut(field, "=")
			key = strings.ToLower(strings.TrimSpace(key))
			val = strings.TrimSpace(val)

			if key == "" {
				continue
			}
			if !hasValue {
				// A bare field other than `v=wecert1` is meaningless; only the
				// version marker itself may omit its value.
				if key != DeclarationVersion {
					return nil, fmt.Errorf("record %q: field %q is neither key=value nor the bare version marker %q",
						record, field, DeclarationVersion)
				}
				continue
			}
			if prev, dup := given[key]; dup && prev != val {
				return nil, fmt.Errorf("record %q: key %q is given twice with different values (%q and %q)",
					record, key, prev, val)
			}
			given[key] = val

			switch key {
			case "v":
				if val != DeclarationVersion {
					return nil, fmt.Errorf("record %q: unsupported declaration version %q (want %q)",
						record, val, DeclarationVersion)
				}
			case "wildcard":
				b, err := parseBool(val)
				if err != nil {
					return nil, fmt.Errorf("record %q: wildcard: %w", record, err)
				}
				d.Wildcard = b
			case "profile":
				// Validated here, not at document-write time. A bad value reaching
				// config.NormalizeCertificates failed Commit for every certificate in every later
				// round (the document and the state file were never written) until someone edited
				// DNS -- while this package's contract is that one bad declaration is recorded as a
				// rejection and skipped.
				if !config.ValidProfile(val) {
					return nil, fmt.Errorf("record %q: unknown profile %q (want %s/%s/%s)",
						record, val, config.ProfileClassic, config.ProfileTLSServer, config.ProfileShortLived)
				}
				d.Profile = val
			case "keytype":
				if !config.ValidKeyType(val) {
					return nil, fmt.Errorf("record %q: unknown keyType %q (want %s/%s/%s/%s)",
						record, val, config.KeyTypeECDSAP256, config.KeyTypeECDSAP384,
						config.KeyTypeRSA2048, config.KeyTypeRSA4096)
				}
				d.KeyType = val
			case "deploy":
				b, err := parseBool(val)
				if err != nil {
					return nil, fmt.Errorf("record %q: deploy: %w", record, err)
				}
				d.Deploy = &b
			default:
				return nil, fmt.Errorf("record %q: unknown key %q "+
					"(known: v, wildcard, profile, keytype, deploy); "+
					"a typo here would silently do nothing, so it is rejected instead", record, key)
			}
		}
	}
	return d, nil
}

// splitFields cuts the TXT content into individual fields.
//
// It accepts space, comma and semicolon separators alike: someone typing TXT by
// hand in a DNS console will not remember which one to use, and supporting an
// extra separator is far cheaper than debugging "the declaration did not apply".
func splitFields(v string) []string {
	v = strings.TrimSpace(v)
	v = strings.Trim(v, `"`)
	if v == "" {
		return nil
	}
	return strings.FieldsFunc(v, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
}

func parseBool(v string) (bool, error) {
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	}
	return false, fmt.Errorf("want 1/0, true/false, yes/no or on/off, got %q", v)
}
