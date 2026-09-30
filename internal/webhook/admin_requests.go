package webhook

import (
	"errors"
	"fmt"
	"net/http"
)

// Typed request bodies for the console admin surface. Decoding into structs
// (rather than map[string]any + fmt.Sprint) means a missing field is "" instead
// of the string "<nil>", and a wrong type is a 400 instead of a silent coercion.

// DNSCredential selects how DNS-01 authenticates for one certificate.
type DNSCredential struct {
	Provider string `json:"provider"`
	// Cred is "reused", "token", or "file".
	Cred  string `json:"cred"`
	Token string `json:"token"`
	File  string `json:"file"`
}

// CreateCertificateRequest is POST /admin/certificates.
type CreateCertificateRequest struct {
	Name        string         `json:"name"`
	Domains     []string       `json:"domains"`
	Profile     string         `json:"profile"`
	KeyType     string         `json:"keyType"`
	RenewBefore string         `json:"renewBefore"`
	// Deploy is "clb", "nginx", or "none".
	Deploy string        `json:"deploy"`
	UIN    string        `json:"uin"`
	DNS    *DNSCredential `json:"dns"`
}

// AddAccountRequest is POST /admin/accounts.
type AddAccountRequest struct {
	Name      string `json:"name"`
	UIN       string `json:"uin"`
	Cred      string `json:"cred"`
	Cloud     string `json:"cloud"`
	SecretID  string `json:"secretId"`
	SecretKey string `json:"secretKey"`
	KeyPath   string `json:"keyPath"`
}

// CreateListenerRequest opens a new HTTPS listener during a bind.
type CreateListenerRequest struct {
	Port int `json:"port"`
	Name string `json:"name"`
	// SNI is nil when absent, which means the default (on).
	SNI *bool `json:"sni"`
}

// SNIMode reports whether this listener should use SNI (default on).
func (c *CreateListenerRequest) SNIMode() bool {
	if c == nil || c.SNI == nil {
		return true
	}
	return *c.SNI
}

// BindCertificateRequest is POST /admin/certificates/{name}/bind.
type BindCertificateRequest struct {
	LoadBalancerID string                 `json:"loadBalancerId"`
	ListenerID     string                 `json:"listenerId"`
	Region         string                 `json:"region"`
	SNIDomain      string                 `json:"sniDomain"`
	CreateListener *CreateListenerRequest `json:"createListener"`
}

// InvalidRequestError marks a client-side problem (bad field, rejected name,
// out-of-range value). Admin handlers answer 400 for it, not 503: a rejected
// input is not a reason to claim the daemon is unavailable.
type InvalidRequestError struct{ Msg string }

func (e *InvalidRequestError) Error() string { return e.Msg }

// InvalidRequestf builds a client-error for the admin surface.
func InvalidRequestf(format string, a ...any) error {
	return &InvalidRequestError{Msg: fmt.Sprintf(format, a...)}
}

// statusForError picks the HTTP status for an admin op failure.
func statusForError(err error) int {
	var ir *InvalidRequestError
	if errors.As(err, &ir) {
		return http.StatusBadRequest
	}
	return http.StatusServiceUnavailable
}

// writeOpError answers an admin op failure with the right status.
func writeOpError(w http.ResponseWriter, err error) {
	writeJSON(w, statusForError(err), map[string]string{"error": err.Error()})
}
