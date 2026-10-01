package webhook

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/susunola/wecert/internal/config"
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
	Name        string   `json:"name"`
	Domains     []string `json:"domains"`
	Profile     string   `json:"profile"`
	KeyType     string   `json:"keyType"`
	RenewBefore string   `json:"renewBefore"`
	// Deploy is "clb", "nginx", or "none".
	Deploy string         `json:"deploy"`
	UIN    string         `json:"uin"`
	DNS    *DNSCredential `json:"dns"`
}

// ResolveDeploy maps the console's deploy choice onto the enabled flag and the
// deploy target recorded for a certificate.
//
// "clb" deliberately leaves the target empty: it means "push this wherever the
// daemon already points", so an operator who later reconfigures the process for
// nginx does not find older rows pinned to a backend they stopped using.
// "nginx" pins the row. Anything else (including "none") disables deployment.
func ResolveDeploy(value string) (enabled bool, target string) {
	switch strings.TrimSpace(value) {
	case "clb":
		return true, ""
	case "nginx":
		return true, config.DeployTargetNginx
	}
	return false, ""
}

// AddAccountRequest is POST /admin/accounts.
type AddAccountRequest struct {
	Name string `json:"name"`
	// UIN is optional for static AK/SK: the daemon can leave it blank and the
	// console groups the account by name instead.
	UIN   string `json:"uin"`
	Cred  string `json:"cred"`
	Cloud string `json:"cloud"`
	// Site is "china", "international", or "" for auto-detect. Tencent Cloud
	// runs two separate account systems with different API root domains.
	Site      string `json:"site"`
	SecretID  string `json:"secretId"`
	SecretKey string `json:"secretKey"`
	KeyPath   string `json:"keyPath"`
}

// CreateListenerRequest opens a new HTTPS listener during a bind.
type CreateListenerRequest struct {
	Port int    `json:"port"`
	Name string `json:"name"`
	// SNI is nil when absent, which means the default (on).
	SNI *bool `json:"sni"`
}

// Sanitized returns a copy without the secret material. The console registry
// keeps the provider and the credential *kind* for display; the token itself
// already lives in a 0600 file on the daemon host and must not be duplicated
// in plain text beside the state database.
func (d DNSCredential) Sanitized() DNSCredential {
	d.Token = ""
	d.File = ""
	return d
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
