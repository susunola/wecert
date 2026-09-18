package acme

import (
	"testing"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/state"
)

// An interrupted registration is recovered, not duplicated.
//
// EnsureAccount persists the key before registering, so the row a crash leaves behind is
// "key on disk, kid empty". The next start must register with THAT key -- a CA returns the
// existing account for a key it already knows -- and backfill the kid, rather than
// generating a fresh key and registering a second account against the per-IP quota.
func TestEnsureAccountRecoversAnUnrecordedRegistration(t *testing.T) {
	fake, store, cfg := accountFixture(t)

	// The shape an interrupted first run leaves: the key was persisted before the
	// registration, the kid never was.
	key, err := GenerateKey(config.KeyTypeECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := MarshalPrivateKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutAccount(&state.Account{Directory: cfg.ACME.Directory, PrivateKeyPEM: keyPEM}); err != nil {
		t.Fatal(err)
	}

	core, err := EnsureAccount(cfg, store, fake.srv.Client())
	if err != nil {
		t.Fatalf("a key-only row must be completed by registering with it: %v", err)
	}
	if core == nil {
		t.Fatal("EnsureAccount returned no core")
	}

	stored, err := store.GetAccount(cfg.ACME.Directory)
	if err != nil {
		t.Fatal(err)
	}
	if stored.KID == "" {
		t.Error("the registration must backfill the kid")
	}
	if string(stored.PrivateKeyPEM) != string(keyPEM) {
		t.Error("the key changed, so a SECOND account was registered instead of recovering the " +
			"interrupted one -- and the account the CA created for the first key is orphaned")
	}
}

// The kid backfill is the only thing a completed recovery writes: the pre-persist must not
// clobber a row that already has a kid (the ordinary "load the stored account" path).
func TestEnsureAccountKeepsACompleteRowUntouched(t *testing.T) {
	fake, store, cfg := accountFixture(t)

	if _, err := EnsureAccount(cfg, store, fake.srv.Client()); err != nil {
		t.Fatalf("first: %v", err)
	}
	first, err := store.GetAccount(cfg.ACME.Directory)
	if err != nil {
		t.Fatal(err)
	}

	// A completed row short-circuits before any network call; refusing registration at the
	// fake makes a re-registration fail loudly instead of passing unnoticed.
	fake.omitAccountLocation.Store(true)
	if _, err := EnsureAccount(cfg, store, fake.srv.Client()); err != nil {
		t.Fatalf("a complete account row must be loaded, not re-registered: %v", err)
	}
	second, err := store.GetAccount(cfg.ACME.Directory)
	if err != nil {
		t.Fatal(err)
	}
	if second.KID != first.KID || string(second.PrivateKeyPEM) != string(first.PrivateKeyPEM) {
		t.Error("a complete account row was modified")
	}
}
