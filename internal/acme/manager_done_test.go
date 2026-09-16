package acme

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"

	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/state"
)

func TestLocalOnlyRenewalClearsDeploymentStateWithoutRetiringLiveCloudCert(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
	cert.Deploy.Enabled = false

	// The ID of the certificate that is being left behind is the only local record that
	// it exists, and nothing else in the system will mention it again. Capture the log so
	// "it was dropped" cannot regress into "it vanished".
	var logs bytes.Buffer
	m.log = slog.New(slog.NewTextHandler(&logs, nil))

	oldExpiry, newExpiry := time.Now().Add(24*time.Hour), time.Now().Add(90*24*time.Hour)
	st := &state.CertState{Name: cert.Name, NotAfter: oldExpiry, CertURL: "https://ca.test/old", CertPEM: selfSignedCertPEM(t, oldExpiry, "example.com"), KeyPEM: []byte("old-key"), DeployedCertID: "cloud-old", DeployConfirmed: true}
	if err := store.PutCert(st); err != nil {
		t.Fatal(err)
	}
	key, err := GenerateKey(cert.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := MarshalPrivateKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutOrder(&state.Order{CertName: cert.Name, KeyPEM: keyPEM}); err != nil {
		t.Fatal(err)
	}
	fake.certPEM = selfSignedCertPEM(t, newExpiry, "example.com")
	fake.orders = []legoacme.ExtendedOrder{{Order: legoacme.Order{Status: "valid", Certificate: "https://ca.test/new"}, Location: "https://ca.test/order/new"}}
	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if got.DeployedCertID != "" || got.DeployConfirmed {
		t.Fatalf("local-only renewal must not inherit cloud deployment state: %+v", got)
	}
	retired, err := store.ListRetiredCertsBefore(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(retired) != 0 {
		t.Fatalf("the old cloud certificate may still be bound, so local-only renewal must not retire it: %+v", retired)
	}
	if !strings.Contains(logs.String(), "cloud-old") {
		t.Errorf("the ID of the certificate that is left behind must be logged, got:\n%s", logs.String())
	}
}

func TestReapRetiredKeepsQueueWhenCloudDeploymentIsDisabled(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.AddRetiredCert("cloud-old", "example-com"); err != nil {
		t.Fatal(err)
	}
	m := newManager(store, nil, &fakeSolver{}, fakeKeyAuth{}, deploy.Noop{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.now = func() time.Time { return time.Now().Add(8 * 24 * time.Hour) }
	m.ReapRetired(context.Background())
	retired, err := store.ListRetiredCertsBefore(time.Now().Add(24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(retired) != 1 || retired[0].CertID != "cloud-old" {
		t.Fatalf("Noop must not erase an undeleted cloud certificate from the queue: %+v", retired)
	}
}
