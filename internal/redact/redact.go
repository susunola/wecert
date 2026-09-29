// Package redact strips credentials from free text before it leaves the process.
//
// One implementation for every outbound face: notify payloads, the journal, and
// the LastError column that /hook/status and /api/inventory expose to a
// read-only token. Duplicating the rule per caller is how one of them gets
// forgotten.
package redact

import (
	"net/url"
	"regexp"
	"strings"
)

// Secrets strips credentials from free text. URLs lose userinfo, path and query;
// bearer tokens, AWS/Tencent key ids, PEM blocks and common key=value secrets are
// replaced. The result is truncated so a long stack cannot re-ship a secret in a
// tail the operator never scrolls to.
func Secrets(s string) string {
	s = urlRegexp.ReplaceAllStringFunc(s, func(u string) string {
		return URL(u)
	})
	s = bearerRegexp.ReplaceAllString(s, "$1[redacted]")
	s = accessKeyRegexp.ReplaceAllString(s, "[redacted-access-key]")
	s = pemRegexp.ReplaceAllString(s, "[redacted-pem]")
	s = keyValSecretRegexp.ReplaceAllStringFunc(s, func(m string) string {
		i := strings.IndexByte(m, '=')
		if i < 0 {
			i = strings.IndexByte(m, ':')
		}
		if i < 0 {
			return "[redacted]"
		}
		return m[:i+1] + "[redacted]"
	})
	if len(s) > 512 {
		s = s[:512] + "…"
	}
	return s
}

// URL keeps a notification target's scheme and host and withholds everything else.
// A chat or CI notification URL IS a credential (Slack, Feishu, DingTalk put the
// secret in the path).
func URL(raw string) string {
	if raw == "" {
		return "(no notification URL)"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(notification URL withheld)"
	}
	out := u.Scheme + "://" + u.Host
	if u.Path != "" && u.Path != "/" {
		out += "/...(path withheld)"
	}
	if u.RawQuery != "" || u.Fragment != "" {
		out += "?..."
	}
	return out
}

var (
	urlRegexp          = regexp.MustCompile(`https?://[^\s]+`)
	bearerRegexp       = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._\-+/=]{8,}`)
	accessKeyRegexp    = regexp.MustCompile(`\b(?:AKIA|ASIA|AKID)[0-9A-Za-z]{12,}\b`)
	pemRegexp          = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----`)
	keyValSecretRegexp = regexp.MustCompile(`(?i)\b(?:secret[_-]?key|access[_-]?key|api[_-]?token|api[_-]?key|password|token|authorization)["']?\s*[:=]\s*["']?[A-Za-z0-9._\-+/=]{8,}`)
)
