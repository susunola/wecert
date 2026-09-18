package acme

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	legoacme "github.com/go-acme/lego/v4/acme"

	"github.com/susunola/wecert/internal/config"
	"github.com/susunola/wecert/internal/deploy"
	"github.com/susunola/wecert/internal/state"
)

// stagedDeployer is a Deployer that also implements StagedDeployer and RetryableDeployer, so
// the download path's upload/rebind split and its resume branch can both be exercised.
//
// There was no double for either interface before this file, which is why the whole staged
// path shipped untested.
type stagedDeployer struct {
	uploadID  string
	uploadErr error
	uploads   int

	// rebindErr makes the asynchronous rebind fail after a successful upload -- the shape the
	// durable boundary exists for.
	rebindErr error
	rebinds   int

	resumes     int
	resumedWith string
}

func (s *stagedDeployer) Deploy(_ context.Context, _, oldID string, _, _ []byte) (string, error) {
	return oldID, nil
}

func (s *stagedDeployer) Delete(_ context.Context, _ string) error { return nil }

func (s *stagedDeployer) Bindings(_ context.Context, _ string) (int, bool, error) {
	return 0, true, nil
}

func (s *stagedDeployer) Upload(_ context.Context, _ string, _, _ []byte) (string, error) {
	s.uploads++
	return s.uploadID, s.uploadErr
}

func (s *stagedDeployer) DeployUploaded(_ context.Context, _, _, uploadedID string) (string, error) {
	s.rebinds++
	// On error the deployer still hands back the ID that was uploaded successfully -- that is
	// the documented contract and the caller depends on it.
	return uploadedID, s.rebindErr
}

func (s *stagedDeployer) ResumeDeploy(_ context.Context, _, _, uploadedID string) (string, error) {
	s.resumes++
	s.resumedWith = uploadedID
	return uploadedID, s.rebindErr
}

// seedIssuedCertificate puts an already-issued, already-bound certificate into the store and a
// fresh order alongside it, so Reconcile takes the renewal path instead of first issuance.
func seedIssuedCertificate(t *testing.T, store *state.Store, cert *config.Certificate, liveID string) {
	t.Helper()

	oldExpiry := time.Now().Add(24 * time.Hour)
	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: oldExpiry, CertURL: "https://ca.test/old",
		CertPEM:        selfSignedCertPEM(t, oldExpiry, cert.Domains...),
		KeyPEM:         []byte("old-key"),
		DeployedCertID: liveID, DeployConfirmed: true,
	}); err != nil {
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
}

// ---------- discarding an order must not leak a pending upload ----------

// An order can carry the ID of a certificate that was uploaded to Tencent Cloud but whose
// asynchronous rebind never finished. Discarding the order deletes the row, and nothing else in
// the system mentions that certificate again.
//
// Without reclaiming it, the certificate is in neither the certificates table nor the retired
// table, ReapRetired never sees it, and it occupies the account's uploaded-certificate quota
// forever -- and quota exhaustion is what stops renewal. Every path that discards an order goes
// through here: an expired order, a changed domain set, an order the CA declared invalid, and a
// certificate removed from the desired state.
func TestDiscardingAnOrderReclaimsThePendingUpload(t *testing.T) {
	store, m, _, cert := newAPITestHarness(t, []string{"example.com"})

	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: time.Now().Add(80 * 24 * time.Hour),
		CertURL: "https://ca.test/live", DeployedCertID: "ap-live",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutOrder(&state.Order{
		CertName: cert.Name, OrderURL: "https://ca.test/order",
		DeploymentCertID: "ap-uploaded",
	}); err != nil {
		t.Fatal(err)
	}

	if err := m.discardOrder(context.Background(), cert.Name); err != nil {
		t.Fatalf("discardOrder: %v", err)
	}

	retired, err := store.ListRetiredCertsBefore(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, r := range retired {
		if r.CertID == "ap-uploaded" {
			found = true
			if r.CertName != cert.Name {
				t.Errorf("reclaimed under cert name %q, want %q", r.CertName, cert.Name)
			}
		}
	}
	if !found {
		t.Fatalf("the uploaded certificate ap-uploaded was not queued for reclaim, so it would "+
			"occupy the Tencent Cloud certificate quota forever. retired=%+v", retired)
	}

	// Discarding must still discard.
	if o, err := store.GetOrder(cert.Name); err != nil {
		t.Fatal(err)
	} else if o != nil {
		t.Fatalf("the order row is still present after discardOrder: %+v", o)
	}
}

// The counterpart: when the pending ID is the certificate actually in service, it must not be
// queued for reclamation. This is what keeps the fix above from retiring the live certificate on
// the ordinary success path, where the order row can still hold the ID just deployed.
func TestDiscardingAnOrderLeavesTheCertificateInServiceAlone(t *testing.T) {
	store, m, _, cert := newAPITestHarness(t, []string{"example.com"})

	if err := store.PutCert(&state.CertState{
		Name: cert.Name, NotAfter: time.Now().Add(80 * 24 * time.Hour),
		CertURL: "https://ca.test/live", DeployedCertID: "ap-live",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutOrder(&state.Order{
		CertName: cert.Name, OrderURL: "https://ca.test/order",
		DeploymentCertID: "ap-live",
	}); err != nil {
		t.Fatal(err)
	}

	if err := m.discardOrder(context.Background(), cert.Name); err != nil {
		t.Fatalf("discardOrder: %v", err)
	}

	retired, err := store.ListRetiredCertsBefore(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(retired) != 0 {
		t.Fatalf("ap-live is the certificate in service and must not be reclaimed: %+v", retired)
	}
}

// Nothing pending, nothing to reclaim: a discard must not invent a queue entry.
func TestDiscardingAnOrderWithNothingPendingRetiresNothing(t *testing.T) {
	store, m, _, cert := newAPITestHarness(t, []string{"example.com"})

	if err := store.PutOrder(&state.Order{
		CertName: cert.Name, OrderURL: "https://ca.test/order",
	}); err != nil {
		t.Fatal(err)
	}

	if err := m.discardOrder(context.Background(), cert.Name); err != nil {
		t.Fatalf("discardOrder: %v", err)
	}
	retired, err := store.ListRetiredCertsBefore(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(retired) != 0 {
		t.Fatalf("nothing was uploaded, so nothing may be reclaimed: %+v", retired)
	}
}

// ---------- the staged deploy path ----------

// The durable boundary: the uploaded ID is on disk before the asynchronous rebind starts, so a
// crash or a timeout resumes the same certificate instead of uploading another copy.
func TestStagedDeployPersistsTheUploadedIDBeforeTheRebind(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
	cert.Deploy.Enabled = true

	dep := &stagedDeployer{uploadID: "ap-uploaded", rebindErr: errors.New("rebind timed out")}
	m.deployer = dep

	seedIssuedCertificate(t, store, cert, "ap-live")
	fake.certNotAfter = time.Now().Add(90 * 24 * time.Hour)
	fake.orders = []legoacme.ExtendedOrder{{Order: legoacme.Order{
		Status: "valid", Certificate: "https://ca.test/new"}, Location: "https://ca.test/order/new"}}

	if err := m.Reconcile(context.Background(), cert); err == nil {
		t.Fatal("a failed rebind must be reported as a failed pass")
	}

	if dep.uploads != 1 || dep.rebinds != 1 {
		t.Fatalf("want exactly one upload and one rebind attempt, got uploads=%d rebinds=%d",
			dep.uploads, dep.rebinds)
	}

	// The order row is the durable record: the next round can only resume if the ID survived.
	o, err := store.GetOrder(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if o == nil {
		t.Fatal("the order was discarded after a failed deploy; the pending upload is unrecoverable")
	}
	if o.DeploymentCertID != "ap-uploaded" {
		t.Fatalf("the uploaded ID must survive the failed rebind so the next round can resume it, got %q",
			o.DeploymentCertID)
	}
}

// The next round must resume the certificate already in Tencent Cloud instead of uploading a
// second copy. Repeatable=true means uploads are never deduplicated, so a retry that uploads
// again leaks one certificate per attempt.
func TestStagedDeployResumesTheUploadedCertificateOnALaterRound(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
	cert.Deploy.Enabled = true

	dep := &stagedDeployer{uploadID: "ap-duplicate"}
	m.deployer = dep

	seedIssuedCertificate(t, store, cert, "ap-live")

	// The previous round uploaded this one and did not finish.
	o, err := store.GetOrder(cert.Name)
	if err != nil || o == nil {
		t.Fatalf("order seeded by the harness is missing: %v", err)
	}
	o.DeploymentCertID = "ap-uploaded"
	if err := store.PutOrder(o); err != nil {
		t.Fatal(err)
	}

	fake.certNotAfter = time.Now().Add(90 * 24 * time.Hour)
	fake.orders = []legoacme.ExtendedOrder{{Order: legoacme.Order{
		Status: "valid", Certificate: "https://ca.test/new"}, Location: "https://ca.test/order/new"}}

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("resuming a pending deployment must succeed: %v", err)
	}

	if dep.uploads != 0 {
		t.Errorf("uploaded %d more copies despite a pending certificate; Repeatable=true means "+
			"each one leaks against the account quota", dep.uploads)
	}
	if dep.resumes != 1 {
		t.Fatalf("want exactly one resume, got %d", dep.resumes)
	}
	if dep.resumedWith != "ap-uploaded" {
		t.Errorf("resumed with %q, want the ID persisted by the earlier round", dep.resumedWith)
	}
}

// On the ordinary success path the newly bound certificate must not be queued for reclamation.
//
// The order row still holds the ID that was just deployed -- the clear is a separate write -- so
// without the live-ID guard the reclaim pass would delete the certificate now in service.
func TestSuccessfulStagedDeployDoesNotReclaimTheCertificateItJustBound(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
	cert.Deploy.Enabled = true

	dep := &stagedDeployer{uploadID: "ap-new"}
	m.deployer = dep

	seedIssuedCertificate(t, store, cert, "ap-old")
	fake.certNotAfter = time.Now().Add(90 * 24 * time.Hour)
	fake.orders = []legoacme.ExtendedOrder{{Order: legoacme.Order{
		Status: "valid", Certificate: "https://ca.test/new"}, Location: "https://ca.test/order/new"}}

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	retired, err := store.ListRetiredCertsBefore(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var oldFound bool
	for _, r := range retired {
		if r.CertID == "ap-new" {
			t.Fatalf("the certificate just bound to the listener was queued for reclamation: %+v", retired)
		}
		if r.CertID == "ap-old" {
			oldFound = true
		}
	}
	if !oldFound {
		t.Fatalf("the superseded certificate should be reclaimed: %+v", retired)
	}
}

// A renewal of a certificate nobody has bound yet must converge, not fail forever.
//
// deploy.enabled starts with one upload and a manual bind ("once bound, later renewals switch it
// automatically"). If the renewal window arrives before that bind happens, the cloud has nothing
// to switch: UpdateCertificateInstance answers FailedOperation.CertificateDeployInstanceEmpty
// (observed on a real account, docs/e2e-run-2026-09-18-credentialed.md 5.3). Treating that as a
// failed deploy meant the pass failed on every round, the promotion never ran, and the state kept
// pointing at the certificate that was expiring -- while each cycle issued and uploaded another
// one. It is the documented first-issuance state, so it promotes like one: the new upload becomes
// the recorded cloud certificate, DeployConfirmed stays false, and the operator is told again
// which certificate to bind.
func TestARenewalWithNothingBoundYetConvergesAsAFirstBind(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
	cert.Deploy.Enabled = true

	dep := &stagedDeployer{uploadID: "cloud-new", rebindErr: deploy.ErrNothingBoundYet}
	m.deployer = dep
	var logs bytes.Buffer
	m.log = slog.New(slog.NewTextHandler(&logs, nil))

	seedIssuedCertificate(t, store, cert, "cloud-old")
	fake.certNotAfter = time.Now().Add(90 * 24 * time.Hour)
	fake.orders = []legoacme.ExtendedOrder{{Order: legoacme.Order{
		Status: "valid", Certificate: "https://ca.test/new"}, Location: "https://ca.test/order/new"}}

	if err := m.Reconcile(context.Background(), cert); err != nil {
		t.Fatalf("nothing is bound, so there was no switch to fail: %v", err)
	}

	// The operator hint is the only thing that tells a human what to do about this state, and the
	// wording is load-bearing rather than cosmetic: it used to say "bind either certificate once in
	// the CLB console", while the very same round retires the predecessor onto the reclaim list --
	// so following it by binding the OLD certificate leaves the row wecert tracks unbound, the next
	// pass reports "nothing bound yet" again, uploads a THIRD certificate and burns another issuance.
	// The hint therefore has to name this upload (and the field that carries its id).
	if !strings.Contains(logs.String(), "bind this certificate (the certId above") ||
		!strings.Contains(logs.String(), `certId=cloud-new`) {
		t.Errorf("the hint must name the certificate this upload created, with the field that "+
			"carries its id, so the instruction is followable; got:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), "either certificate") {
		t.Error("the hint must not offer a choice of certificate: binding the predecessor leaves the " +
			"tracked row unbound and costs another issuance next round")
	}

	st, err := store.GetCert(cert.Name)
	if err != nil {
		t.Fatal(err)
	}
	if st.DeployedCertID != "cloud-new" {
		t.Errorf("the renewed certificate must become the recorded cloud certificate, got %q; "+
			"otherwise the state keeps pointing at the certificate that is expiring", st.DeployedCertID)
	}
	if st.DeployConfirmed {
		t.Error("nothing is bound, so the deployment must not be confirmed: the deployed metric " +
			"would claim a certificate is serving traffic when no listener has it")
	}
	// X.509 timestamps have second precision, so compare truncated values.
	if !st.NotAfter.Truncate(time.Second).Equal(fake.certNotAfter.Truncate(time.Second)) {
		t.Errorf("the renewal must be recorded (notAfter %s), got %s", fake.certNotAfter, st.NotAfter)
	}
	if st.ConsecutiveFailures != 0 {
		t.Errorf("a pending first bind is not a failure, got %d consecutive failures", st.ConsecutiveFailures)
	}
	if dep.uploads != 1 {
		t.Errorf("exactly one upload belongs here, got %d", dep.uploads)
	}
	// The next round must not re-upload: the order is gone and the state names the new id.
	if o, err := store.GetOrder(cert.Name); err != nil || o != nil {
		t.Errorf("the order must be finished, got %+v (err=%v)", o, err)
	}

	// The upload being replaced must not be forgotten. Nothing is bound to it (which is what makes
	// the pending-first-bind reading correct), and the row that named it has just been overwritten,
	// so without a reclaim record the id is in neither certificates nor retired_certificates and the
	// certificate is billed against the account quota forever.
	retired, err := store.ListRetiredCertsBefore(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var reclaimed bool
	for _, r := range retired {
		if r.CertID == "cloud-old" {
			reclaimed = true
		}
	}
	if !reclaimed {
		t.Errorf("the replaced upload (%q) must be queued for reclamation, got %+v", "cloud-old", retired)
	}
}

// An uploaded certificate whose resume-anchor write fails must still be reclaimable.
//
// The anchor is what lets the next pass resume instead of uploading again; when recording it fails,
// the order cannot name the copy and the promotion never runs, so the id lived only in a log line:
// not in certificates, not in retired_certificates, therefore invisible to ReapRetired and billed
// against the account's uploaded-certificate quota forever, while the next pass uploaded a second
// copy. The reclaim list is the only place left, and it is the right one -- nothing was ever bound
// to that copy (the deploy that would have switched to it never ran), and Delete asks the cloud to
// refuse if anything does reference it.
//
// The write is made to fail with a SQLite trigger, which is the same shape as a full disk: the read
// that loaded the order succeeded, the UPDATE that would record the anchor does not.
func TestAnUnrecordableResumeAnchorLeavesTheUploadReclaimable(t *testing.T) {
	store, m, fake, cert := newAPITestHarness(t, []string{"example.com"})
	cert.Deploy.Enabled = true

	dep := &stagedDeployer{uploadID: "cloud-anchorless"}
	m.deployer = dep
	seedIssuedCertificate(t, store, cert, "cloud-live")
	fake.certNotAfter = time.Now().Add(90 * 24 * time.Hour)
	fake.orders = []legoacme.ExtendedOrder{{Order: legoacme.Order{
		Status: "valid", Certificate: "https://ca.test/new"}, Location: "https://ca.test/order/new"}}

	// Only the anchor write fails: the order is loaded, the UPDATE that would record
	// deployment_cert_id is refused. Same shape as a full disk. The trigger is created through the
	// admin connection the harness exposes for exactly this.
	if err := store.ExecForTest(`CREATE TRIGGER r7b_no_anchor BEFORE UPDATE ON orders
		WHEN NEW.deployment_cert_id <> '' AND OLD.deployment_cert_id = ''
		BEGIN SELECT RAISE(ABORT, 'disk full'); END`); err != nil {
		t.Fatalf("create the fault trigger: %v", err)
	}

	if err := m.Reconcile(context.Background(), cert); err == nil {
		t.Fatal("the anchor write is refused, so the pass must fail")
	}
	if dep.uploads != 1 {
		t.Fatalf("the fixture must reach the upload, got %d", dep.uploads)
	}

	retired, err := store.ListRetiredCertsBefore(m.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, r := range retired {
		if r.CertID == "cloud-anchorless" {
			found = true
		}
	}
	if !found {
		t.Errorf("the uploaded certificate %q is named by no row (the order could not record the "+
			"anchor and the promotion never ran), so ReapRetired can never see it and it occupies the "+
			"account's uploaded-certificate quota forever. Reclaim list: %+v", "cloud-anchorless", retired)
	}
}
