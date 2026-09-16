package acme

import (
	"encoding/base64"
	"net/http"

	legoacme "github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"
)

// API is **every** ACME operation Manager needs.
//
// It is factored out so the whole issuance flow can be unit tested. Before this,
// only the cleanup path had a narrow interface, so the order state machine -- the
// most error-prone and most expensive stretch of this system -- could only be
// covered by standing up a fake ACME HTTP server. That runs, but it cannot answer
// "which methods did it call, in what order", and the order is the entire
// correctness argument here:
//
//   - the order URL must be persisted **immediately** after newOrder returns,
//     before anything else happens
//   - a wildcard and its apex must be "written together, validated together,
//     cleaned up together"
//   - the CSR must be submitted to the finalize URL, not the order URL
//   - the order must carry replaces, or we get no ARI rate-limit exemption
//
// Get any one of these wrong and the price is a 7-day, unrecoverable exact-set limit.
//
// Note that these methods **carry no context**: lego's api.Core is not
// context-aware at all; it leans on http.Client timeouts. Bolting on a ctx parameter
// would only invent a fake interface that "looks cancellable but never cancels" --
// worse than none, because it makes callers believe cancellation actually works.
type API interface {
	// NewOrder creates a new order.
	//
	// ReplacesCertID in opts is the precondition for the ARI rate-limit exemption.
	// Leave it out and nothing errors -- the issuance just burns real quota. That
	// class of "error that never errors" is exactly why we need a fake that can
	// assert on the arguments it was called with.
	NewOrder(domains []string, opts *api.OrderOptions) (legoacme.ExtendedOrder, error)

	// GetOrder reads the order's current state. Idempotent, and the entry point for
	// crash recovery.
	GetOrder(orderURL string) (legoacme.ExtendedOrder, error)

	// UpdateOrderForCSR submits the CSR to the finalize URL.
	//
	// The parameter is named finalizeURL rather than lego's misleading orderURL:
	// pass the order URL and LE treats it as POST-as-GET and fails with
	// "POST-as-GET requests must have an empty payload".
	UpdateOrderForCSR(finalizeURL string, csr []byte) (legoacme.ExtendedOrder, error)

	// GetAuthorization reads the current state of one authorization.
	GetAuthorization(authzURL string) (legoacme.Authorization, error)

	// AcceptChallenge tells the CA to go and validate.
	AcceptChallenge(challengeURL string) error

	// GetCertificate downloads the certificate. With bundle=true it returns the
	// fullchain (leaf + intermediates), which is exactly the format CLB needs.
	GetCertificate(certURL string, bundle bool) ([]byte, []byte, error)

	// RevokeCertificate tells the CA to revoke a certificate (RFC 8555 §7.6).
	//
	// It is here rather than left to a higher layer because the low-level api.Core wecert uses
	// exposes it on CertificateService and nothing in this program called it -- which is the
	// whole reason wecert had no revocation path. The certificate is passed in DER form,
	// base64url-encoded, because that is what the protocol field carries.
	RevokeCertificate(der []byte, reason int) error

	// GetRenewalInfo reads ARI (RFC 9773).
	//
	// It returns the raw *http.Response instead of a parsed structure because the
	// Retry-After header is itself part of the conclusion -- lego already copes with
	// both of its formats (seconds / HTTP-date), and this header decides how long to
	// wait before asking again.
	GetRenewalInfo(certID string) (*http.Response, error)

	// GetKeyAuthorization converts a challenge token into the key authorization --
	// the value that goes into the DNS TXT record.
	GetKeyAuthorization(token string) (string, error)
}

// NewAPI adapts lego's *api.Core to API.
func NewAPI(core *api.Core) API { return coreAPI{core: core} }

// coreAPI is the lego-backed implementation of API.
//
// It deliberately only forwards and never judges: judgment belongs to Manager, and
// every extra line of logic in the adapter is another place only a real ACME run can
// cover -- exactly what this refactor set out to eliminate.
type coreAPI struct{ core *api.Core }

func (c coreAPI) NewOrder(domains []string, opts *api.OrderOptions) (legoacme.ExtendedOrder, error) {
	return c.core.Orders.NewWithOptions(domains, opts)
}

func (c coreAPI) GetOrder(orderURL string) (legoacme.ExtendedOrder, error) {
	return c.core.Orders.Get(orderURL)
}

func (c coreAPI) UpdateOrderForCSR(finalizeURL string, csr []byte) (legoacme.ExtendedOrder, error) {
	return c.core.Orders.UpdateForCSR(finalizeURL, csr)
}

func (c coreAPI) GetAuthorization(authzURL string) (legoacme.Authorization, error) {
	return c.core.Authorizations.Get(authzURL)
}

// AcceptChallenge throws away the ExtendedChallenge lego returns.
//
// Manager only cares whether the notification went out, and forcing fake
// implementations to build a struct they never read just adds assertion-irrelevant
// noise to the tests.
func (c coreAPI) AcceptChallenge(challengeURL string) error {
	_, err := c.core.Challenges.New(challengeURL)
	return err
}

func (c coreAPI) GetCertificate(certURL string, bundle bool) ([]byte, []byte, error) {
	return c.core.Certificates.Get(certURL, bundle)
}

func (c coreAPI) RevokeCertificate(der []byte, reason int) error {
	msg := legoacme.RevokeCertMessage{
		Certificate: base64.RawURLEncoding.EncodeToString(der),
	}
	// Reason 0 is "unspecified", which the CA treats as "omit the reasonCode". Pointing at a
	// zero value here would send reason=0 explicitly, so the field is left nil instead: the
	// protocol calls it optional and the difference is visible in the CRL entry extension.
	if reason != 0 {
		r := uint(reason)
		msg.Reason = &r
	}
	return c.core.Certificates.Revoke(msg)
}

func (c coreAPI) GetRenewalInfo(certID string) (*http.Response, error) {
	return c.core.Certificates.GetRenewalInfo(certID)
}

func (c coreAPI) GetKeyAuthorization(token string) (string, error) {
	return c.core.GetKeyAuthorization(token)
}
