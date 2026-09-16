package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/state"
)

// userAgentVersion is the version reported to the CA. main sets it from the same -ldflags
// value as `wecert -version`, so an ACME-side log lines up with the binary that sent the
// request instead of naming a release that has been superseded for months.
var userAgentVersion = "dev"

// SetUserAgentVersion records the running version for the ACME User-Agent.
// Call once at startup, before any request.
func SetUserAgentVersion(v string) {
	if v != "" {
		userAgentVersion = v
	}
}

// userAgent shows up in ACME requests, so it lines up with the logs when troubleshooting.
func userAgent() string {
	return "wecert/" + userAgentVersion + " (+https://github.com/susunola/wecert)"
}

// NewHTTPClient builds the HTTP client used for ACME.
func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout}
}

// EnsureAccount loads or registers the ACME account, returning a ready-to-use
// low-level api.Core.
//
// We use the low-level api.Core on purpose, not lego's high-level
// certificate.Obtain: the high-level path calls newOrder internally, so we cannot
// persist the order URL and reuse it across restarts -- a crash-restart would
// place a fresh order and walk straight into the
// "5 certificates per exact set of identifiers / 7 days" rate limit.
//
// The account key and the kid both live in SQLite: losing them means a brand-new
// account, needlessly burning another slice of the per-account quota.
func EnsureAccount(cfg *config.Config, store *state.Store, httpClient *http.Client) (*api.Core, error) {
	directory := cfg.ACME.Directory

	acc, err := store.GetAccount(directory)
	if err != nil {
		return nil, err
	}

	if acc != nil && len(acc.PrivateKeyPEM) > 0 {
		key, err := ParsePrivateKeyPEM(acc.PrivateKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("parse the stored account key: %w", err)
		}
		core, err := api.New(httpClient, userAgent(), directory, acc.KID, key)
		if err != nil {
			return nil, fmt.Errorf("initialise the ACME client: %w", err)
		}
		return core, nil
	}

	// First run: generate the account private key and register the account.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate the account key: %w", err)
	}

	core, err := api.New(httpClient, userAgent(), directory, "", key)
	if err != nil {
		return nil, fmt.Errorf("initialise the ACME client: %w", err)
	}

	reg, err := core.Accounts.New(legoacme.Account{
		Contact:              []string{"mailto:" + cfg.ACME.Email},
		TermsOfServiceAgreed: true,
	})
	if err != nil {
		return nil, fmt.Errorf("register the ACME account: %w", err)
	}
	if reg.Location == "" {
		return nil, fmt.Errorf("register the ACME account: the server returned no account URL (kid)")
	}

	keyPEM, err := MarshalPrivateKeyPEM(key)
	if err != nil {
		return nil, err
	}
	if err := store.PutAccount(&state.Account{
		Directory:     directory,
		KID:           reg.Location,
		PrivateKeyPEM: keyPEM,
	}); err != nil {
		return nil, err
	}

	return core, nil
}

// Compile-time assertion: the ECDSA private key used to register accounts must
// satisfy crypto.PrivateKey, otherwise api.New only blows up at runtime.
var _ crypto.PrivateKey = (*ecdsa.PrivateKey)(nil)
