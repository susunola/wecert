package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"sync"
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

// EnsureFailoverAPI initialises the primary account and every configured standby.
// A standby receives a copy of the primary account key only when it has no account
// yet. ACME accounts remain separate per CA directory, while the shared key keeps
// DNS-01 key authorization valid after a transport failover.
func EnsureFailoverAPI(cfg *config.Config, store *state.Store, httpClient *http.Client) (API, error) {
	primary, err := EnsureAccount(cfg, store, httpClient)
	if err != nil {
		return nil, err
	}
	if len(cfg.ACME.FallbackDirectories) == 0 {
		return NewAPI(primary), nil
	}
	account, err := store.GetAccount(cfg.ACME.Directory)
	if err != nil {
		return nil, err
	}
	if account == nil || len(account.PrivateKeyPEM) == 0 {
		return nil, fmt.Errorf("primary ACME account has no persisted key")
	}
	standbys := make([]API, 0, len(cfg.ACME.FallbackDirectories))
	for _, directory := range cfg.ACME.FallbackDirectories {
		// A backup CA may be unavailable for months without making the healthy
		// primary renewal path unavailable. Its account is registered lazily only
		// after a qualifying primary failure.
		standbys = append(standbys, &lazyFallbackAPI{cfg: cfg, directory: directory, store: store, client: httpClient, keyPEM: account.PrivateKeyPEM})
	}
	return NewFailoverAPI(NewAPI(primary), cfg.ACME.Directory, standbys, cfg.ACME.FallbackDirectories)
}

type lazyFallbackAPI struct {
	cfg       *config.Config
	directory string
	store     *state.Store
	client    *http.Client
	keyPEM    []byte
	mu        sync.Mutex
	api       API
}

func (l *lazyFallbackAPI) get() (API, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.api != nil {
		return l.api, nil
	}
	a, err := l.store.GetAccount(l.directory)
	if err != nil {
		return nil, err
	}
	if a == nil || len(a.PrivateKeyPEM) == 0 {
		if err := l.store.PutAccount(&state.Account{Directory: l.directory, PrivateKeyPEM: l.keyPEM}); err != nil {
			return nil, err
		}
	}
	c := *l.cfg
	c.ACME.Directory = l.directory
	core, err := EnsureAccount(&c, l.store, l.client)
	if err != nil {
		return nil, err
	}
	l.api = NewAPI(core)
	return l.api, nil
}

func (l *lazyFallbackAPI) NewOrder(d []string, o *api.OrderOptions) (legoacme.ExtendedOrder, error) {
	a, e := l.get()
	if e != nil {
		return legoacme.ExtendedOrder{}, e
	}
	return a.NewOrder(d, o)
}
func (l *lazyFallbackAPI) GetOrder(u string) (legoacme.ExtendedOrder, error) {
	a, e := l.get()
	if e != nil {
		return legoacme.ExtendedOrder{}, e
	}
	return a.GetOrder(u)
}
func (l *lazyFallbackAPI) UpdateOrderForCSR(u string, c []byte) (legoacme.ExtendedOrder, error) {
	a, e := l.get()
	if e != nil {
		return legoacme.ExtendedOrder{}, e
	}
	return a.UpdateOrderForCSR(u, c)
}
func (l *lazyFallbackAPI) GetAuthorization(u string) (legoacme.Authorization, error) {
	a, e := l.get()
	if e != nil {
		return legoacme.Authorization{}, e
	}
	return a.GetAuthorization(u)
}
func (l *lazyFallbackAPI) AcceptChallenge(u string) error {
	a, e := l.get()
	if e != nil {
		return e
	}
	return a.AcceptChallenge(u)
}
func (l *lazyFallbackAPI) GetCertificate(u string, b bool) ([]byte, []byte, error) {
	a, e := l.get()
	if e != nil {
		return nil, nil, e
	}
	return a.GetCertificate(u, b)
}
func (l *lazyFallbackAPI) RevokeCertificate(d []byte, r int) error {
	a, e := l.get()
	if e != nil {
		return e
	}
	return a.RevokeCertificate(d, r)
}
func (l *lazyFallbackAPI) GetRenewalInfo(id string) (*http.Response, error) {
	a, e := l.get()
	if e != nil {
		return nil, e
	}
	return a.GetRenewalInfo(id)
}
func (l *lazyFallbackAPI) GetKeyAuthorization(t string) (string, error) {
	a, e := l.get()
	if e != nil {
		return "", e
	}
	return a.GetKeyAuthorization(t)
}

// Compile-time assertion: the ECDSA private key used to register accounts must
// satisfy crypto.PrivateKey, otherwise api.New only blows up at runtime.
var _ crypto.PrivateKey = (*ecdsa.PrivateKey)(nil)
