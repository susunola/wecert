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
//
// The key is persisted BEFORE the account is registered, with an empty kid, and the kid
// is backfilled once registration answers. The other order -- register first, persist
// both -- loses the account entirely when the write fails after a successful
// registration: the CA knows the account, but neither the key nor the kid survives
// locally, so the next start registers a SECOND account. A restart finding a key with an
// empty kid re-registers with that same key, and a CA returns the existing account for a
// key it already knows -- so the interrupted registration is recovered, not duplicated.
func EnsureAccount(cfg *config.Config, store *state.Store, httpClient *http.Client) (*api.Core, error) {
	directory := cfg.ACME.Directory

	acc, err := store.GetAccount(directory)
	if err != nil {
		return nil, err
	}

	var keyPEM []byte
	var key crypto.Signer
	if acc != nil && len(acc.PrivateKeyPEM) > 0 {
		key, err = ParsePrivateKeyPEM(acc.PrivateKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("parse the stored account key: %w", err)
		}
		keyPEM = acc.PrivateKeyPEM
	} else {
		// First run, or a legacy row without a key: generate the account private key and
		// persist it before any network call, so a registration that succeeds while its
		// record fails can still be recovered by the retry above.
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate the account key: %w", err)
		}
		key = k
		keyPEM, err = MarshalPrivateKeyPEM(key)
		if err != nil {
			return nil, err
		}
		if err := store.PutAccount(&state.Account{Directory: directory, PrivateKeyPEM: keyPEM}); err != nil {
			return nil, fmt.Errorf("persist the account key before registering: %w", err)
		}
		// A legacy row without a key cannot keep its kid. That kid names an account
		// registered for a DIFFERENT key: PutAccount just cleared it in the database
		// (kid = excluded.kid), and pairing the leftover in-memory KID with this new key
		// would make every JWS fail for the whole pass -- then register a second account
		// on the next start. Force the re-registration branch below.
		if acc != nil {
			acc.KID = ""
		}
	}

	// A row with a kid is complete: load it without registering. Only when the key that
	// goes with it is the one already stored -- see the legacy-row branch above.
	if acc != nil && acc.KID != "" {
		core, err := api.New(httpClient, userAgent(), directory, acc.KID, key)
		if err != nil {
			return nil, fmt.Errorf("initialise the ACME client: %w", err)
		}
		return core, nil
	}

	// The key is on disk but no kid is recorded -- either this is the first registration or
	// an earlier run was interrupted between the registration and the kid backfill. Both
	// converge on the same call: registering with the stored key.
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

	if err := store.PutAccount(&state.Account{
		Directory:     directory,
		KID:           reg.Location,
		PrivateKeyPEM: keyPEM,
	}); err != nil {
		// The account exists at the CA now, and its key is on disk with an empty kid: the
		// next start re-registers with the same key, which the CA answers with this same
		// account. The registration is recovered, not duplicated -- which is exactly the
		// failure this two-step write exists for.
		return nil, err
	}

	return core, nil
}

// Compile-time assertion: the ECDSA private key used to register accounts must
// satisfy crypto.PrivateKey, otherwise api.New only blows up at runtime.
var _ crypto.PrivateKey = (*ecdsa.PrivateKey)(nil)
