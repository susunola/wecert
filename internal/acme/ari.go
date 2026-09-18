package acme

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-acme/lego/v4/acme/api"
)

// RenewalInfo is the RFC 9773 renewalInfo response.
type RenewalInfo struct {
	SuggestedWindow struct {
		Start time.Time `json:"start"`
		End   time.Time `json:"end"`
	} `json:"suggestedWindow"`
	ExplanationURL string `json:"explanationURL"`
}

// CertID builds the ARI certID per RFC 9773:
//
//	base64url(AKI keyIdentifier) + "." + base64url(DER serial number)
//
// Note the AKI is the keyIdentifier's raw bytes from the extension, not the whole
// extension.
func CertID(leaf *x509.Certificate) (string, error) {
	if len(leaf.AuthorityKeyId) == 0 {
		return "", fmt.Errorf("certificate has no Authority Key Identifier; cannot build an ARI certID")
	}
	aki := base64.RawURLEncoding.EncodeToString(leaf.AuthorityKeyId)
	// RFC 9773 section 4.1 wants the serial **as its DER encoding appears in the
	// certificate**: a positive INTEGER whose top bit is set carries a leading 0x00,
	// or DER would read the value as negative. big.Int.Bytes() drops that byte, so a
	// high-bit serial without it builds a certID the CA cannot match -- and the ARI
	// lookup silently misses, losing the rate-limit exemption.
	der := leaf.SerialNumber.Bytes()
	if len(der) > 0 && der[0]&0x80 != 0 {
		der = append([]byte{0x00}, der...)
	}
	serial := base64.RawURLEncoding.EncodeToString(der)
	return aki + "." + serial, nil
}

// ErrRenewalInfoLongTerm marks a renewalInfo answer that cannot change by retrying: a 404, which
// means the CA does not know this certificate at all (RFC 9773 section 4.3.3).
//
// It exists so the caller can tell it apart from a transient failure: the server's Retry-After is
// the right thing to obey for a 429 or a 5xx, and the wrong thing for "I have never heard of this
// certificate" -- a short header there made the poll come back in a minute instead of the six-hour
// floor, every hour, forever.
var ErrRenewalInfoLongTerm = errors.New("renewalInfo cannot answer for this certificate")

// FetchRenewalInfo queries ARI and also returns the Retry-After the server asked for.
//
// ARI is the single most important piece of this system: a renewal that goes through
// ARI and carries replaces is exempt from every Let's Encrypt rate limit. Skip ARI and
// all you are left with is the "5 certificates per exact set of identifiers / 7 days"
// limit.
func FetchRenewalInfo(core API, certID string) (*RenewalInfo, time.Duration, error) {
	resp, err := core.GetRenewalInfo(certID)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	// lego already handles both Retry-After formats (seconds and HTTP-date) for us.
	var retryAfter time.Duration
	if v := resp.Header.Get("Retry-After"); v != "" {
		if d, err := api.ParseRetryAfter(v); err == nil {
			retryAfter = d
		}
	}

	if resp.StatusCode != http.StatusOK {
		// RFC 9773 section 4.3.3 splits the failures in two. A 404 is LONG-TERM: the CA does not
		// know this certificate (it was issued by another CA, or predates the account), and no
		// amount of retrying changes that -- the server's Retry-After, if it sends one, describes
		// when the answer could differ, not when a new window will appear. Everything else (429,
		// 5xx) is transient, and there the header is exactly what to honour.
		if resp.StatusCode == http.StatusNotFound {
			return nil, 0, fmt.Errorf("%w: renewalInfo returned 404", ErrRenewalInfoLongTerm)
		}
		return nil, retryAfter, fmt.Errorf("renewalInfo returned %d", resp.StatusCode)
	}

	var info RenewalInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&info); err != nil {
		return nil, retryAfter, fmt.Errorf("parse renewalInfo: %w", err)
	}
	if info.SuggestedWindow.End.Before(info.SuggestedWindow.Start) {
		return nil, retryAfter, fmt.Errorf("renewalInfo suggestedWindow is invalid: %s - %s",
			info.SuggestedWindow.Start, info.SuggestedWindow.End)
	}
	return &info, retryAfter, nil
}

// RenewalTime picks a renewal instant deterministically inside the ARI suggested window.
//
// Why it has to be deterministic: if every reconcile re-rolled the dice, each process
// restart would push the renewal further out until it slid past the expiry. Seeding with
// the certificate name + the window start means the same window always yields the same
// instant.
func RenewalTime(name string, start, end time.Time) time.Time {
	if !end.After(start) {
		return start
	}
	span := end.Sub(start)

	h := sha256.Sum256([]byte(name + "|" + start.UTC().Format(time.RFC3339)))

	at := start.Add(time.Duration(binary.BigEndian.Uint64(h[:8]) % uint64(span)))

	// Layer on a deterministic +/-10% jitter so many certificates do not wake up in
	// the same second.
	if jitterSpan := span / 10; jitterSpan > 0 {
		j := time.Duration(binary.BigEndian.Uint64(h[8:16]) % uint64(jitterSpan*2))
		at = at.Add(j - jitterSpan)
	}

	// Jitter can push it outside the window; clamp it back.
	if at.Before(start) {
		return start
	}
	if at.After(end) {
		return end
	}
	return at
}

// DeterministicTime is the fallback renewal instant used when ARI is unavailable.
//
// The semantics are "start at base and spread deterministically by certificate name
// across the spread range", so a few hundred certificates do not all knock on the CA's
// door in the same minute.
func DeterministicTime(name string, base time.Time, spread time.Duration) time.Time {
	if spread <= 0 {
		return base
	}
	h := sha256.Sum256([]byte("fallback|" + name))
	offset := time.Duration(binary.BigEndian.Uint64(h[:8]) % uint64(spread))
	return base.Add(offset)
}
