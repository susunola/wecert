package acme

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	legoacme "github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"
)

// FailoverAPI keeps the primary CA normal path, but can place a *new* order at a
// configured standby when the primary directory is unavailable. All URL-addressed
// ACME operations are then routed back to the CA that minted the URL, so resuming
// an order never crosses issuers.
//
// All participating accounts intentionally use the same account key (see
// EnsureFailoverAPIs). That makes key authorization stable even when the order
// itself was placed at a standby CA.
type FailoverAPI struct {
	primary API
	byHost  map[string]API
	standby []API
}

func NewFailoverAPI(primary API, primaryDirectory string, standbys []API, standbyDirectories []string) (*FailoverAPI, error) {
	if len(standbys) != len(standbyDirectories) {
		return nil, errors.New("ACME fallback core/directory count mismatch")
	}
	f := &FailoverAPI{primary: primary, byHost: map[string]API{}, standby: standbys}
	if err := f.add(primaryDirectory, primary); err != nil {
		return nil, err
	}
	for i := range standbys {
		if err := f.add(standbyDirectories[i], standbys[i]); err != nil {
			return nil, err
		}
	}
	return f, nil
}

func (f *FailoverAPI) add(directory string, api API) error {
	u, err := url.Parse(directory)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid ACME directory %q", directory)
	}
	f.byHost[strings.ToLower(u.Host)] = api
	return nil
}

func (f *FailoverAPI) forURL(raw string) API {
	u, err := url.Parse(raw)
	if err == nil {
		if a := f.byHost[strings.ToLower(u.Host)]; a != nil {
			return a
		}
	}
	// A malformed/unrecognised URL must be sent to the primary so it produces the
	// same actionable error it did before failover existed; guessing a standby is
	// how a persisted order gets silently lost.
	return f.primary
}

func (f *FailoverAPI) NewOrder(domains []string, opts *api.OrderOptions) (legoacme.ExtendedOrder, error) {
	o, err := f.primary.NewOrder(domains, opts)
	if err == nil || !directoryUnavailable(err) {
		return o, err
	}
	for _, standby := range f.standby {
		o, fallbackErr := standby.NewOrder(domains, opts)
		if fallbackErr == nil {
			return o, nil
		}
		if !directoryUnavailable(fallbackErr) {
			return o, fallbackErr
		}
		err = fallbackErr
	}
	return o, err
}
func (f *FailoverAPI) GetOrder(url string) (legoacme.ExtendedOrder, error) {
	return f.forURL(url).GetOrder(url)
}
func (f *FailoverAPI) UpdateOrderForCSR(url string, csr []byte) (legoacme.ExtendedOrder, error) {
	return f.forURL(url).UpdateOrderForCSR(url, csr)
}
func (f *FailoverAPI) GetAuthorization(url string) (legoacme.Authorization, error) {
	return f.forURL(url).GetAuthorization(url)
}
func (f *FailoverAPI) AcceptChallenge(url string) error { return f.forURL(url).AcceptChallenge(url) }
func (f *FailoverAPI) GetCertificate(url string, bundle bool) ([]byte, []byte, error) {
	return f.forURL(url).GetCertificate(url, bundle)
}
func (f *FailoverAPI) RevokeCertificate(der []byte, reason int) error {
	return f.primary.RevokeCertificate(der, reason)
}
func (f *FailoverAPI) GetRenewalInfo(id string) (*http.Response, error) {
	return f.primary.GetRenewalInfo(id)
}
func (f *FailoverAPI) GetKeyAuthorization(token string) (string, error) {
	return f.primary.GetKeyAuthorization(token)
}

// directoryUnavailable is intentionally strict. DNS/authorization errors are
// domain-specific and switching CAs cannot fix them; only transport failures and
// the account-wide new-order refusal qualify for a standby attempt.
func directoryUnavailable(err error) bool {
	// Only a transport-level "could not reach the directory" counts. An arbitrary
	// *url.Error (or any other error that wraps one) is NOT proof the CA is down:
	// a NewOrder that was sent and then lost mid-response may well have created the
	// order on the server, and retrying on standby spends a second exact-set quota.
	var ne net.Error
	if errors.As(err, &ne) && (ne.Timeout() || ne.Temporary() || strings.Contains(ne.Error(), "connection refused") ||
		strings.Contains(ne.Error(), "no such host")) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "connection refused") || strings.Contains(s, "no such host") ||
		strings.Contains(s, "server internal") || strings.Contains(s, "too many new orders")
}
