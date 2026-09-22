package state

import (
	"testing"
	"time"
)

// The orphan-clean mark is what makes the orphan sweep proportional to what needs cleaning
// (docs/backlog.md item 4b): the row of a certificate that left the desired state is kept on
// purpose, so without a durable mark every pass tears the same rows down again. These tests cover
// the store half of it -- the two writers, the guard that decides what "finished" means, and the
// read the sweep uses to see the whole fleet in one query.

func TestOrphanCleanedMarkRoundTrips(t *testing.T) {
	s := openTestStore(t)

	if err := s.PutCert(&CertState{Name: "c1", NotAfter: time.Now().Add(48 * time.Hour)}); err != nil {
		t.Fatalf("PutCert: %v", err)
	}

	// A fresh row, and a row written by a build that never heard of the column, are both
	// "never cleaned" -- the conservative reading, which costs one more teardown.
	st, err := s.GetCert("c1")
	if err != nil || st == nil {
		t.Fatalf("GetCert: %v (st=%v)", err, st)
	}
	if !st.OrphanCleanedAt.IsZero() {
		t.Errorf("a fresh row must not be marked as cleaned, got %s", st.OrphanCleanedAt)
	}

	before := time.Now().Add(-time.Second)
	marked, err := s.MarkOrphanCleaned("c1")
	if err != nil || !marked {
		t.Fatalf("MarkOrphanCleaned = %v, %v; want true, nil", marked, err)
	}

	st, err = s.GetCert("c1")
	if err != nil || st == nil {
		t.Fatalf("GetCert after the mark: %v (st=%v)", err, st)
	}
	if st.OrphanCleanedAt.Before(before) || st.OrphanCleanedAt.After(time.Now().Add(time.Second)) {
		t.Errorf("OrphanCleanedAt = %s, want a timestamp around now", st.OrphanCleanedAt)
	}

	// The sweep reads the same fact, with the expiry its report line prints, in one query.
	rows, err := s.ListOrphanRows()
	if err != nil {
		t.Fatalf("ListOrphanRows: %v", err)
	}
	if len(rows) != 1 || rows[0].Name != "c1" {
		t.Fatalf("ListOrphanRows = %+v, want one row for c1", rows)
	}
	if rows[0].OrphanCleanedAt.IsZero() {
		t.Error("ListOrphanRows must carry the mark: it is what the sweep skips on")
	}
	if !rows[0].NotAfter.Equal(st.NotAfter) {
		t.Errorf("ListOrphanRows not_after = %s, want %s", rows[0].NotAfter, st.NotAfter)
	}
}

// The mark has to survive every other write to the row, because PutCert is a whole-row upsert built
// from a caller's CertState -- and the failure path already synthesises one from a partial read
// (see RecordFailure). One of those rewrites erasing the mark would put the entire fleet's teardown
// cost back on every pass, and nothing in the journal would say why.
func TestNoOtherWriteClobbersTheOrphanCleanedMark(t *testing.T) {
	s := openTestStore(t)

	if err := s.PutCert(&CertState{
		Name: "c1", NotAfter: time.Now().Add(48 * time.Hour),
		CertPEM: []byte("cert"), KeyPEM: []byte("key"), DeployedCertID: "ap-1",
	}); err != nil {
		t.Fatalf("PutCert: %v", err)
	}
	if _, err := s.MarkOrphanCleaned("c1"); err != nil {
		t.Fatalf("MarkOrphanCleaned: %v", err)
	}

	// (a) A caller that builds a CertState from scratch and writes it -- the failure path's shape.
	if err := s.PutCert(&CertState{Name: "c1", LastError: "boom"}); err != nil {
		t.Fatalf("PutCert (whole-row overwrite): %v", err)
	}
	// (b) The narrow failure upsert.
	if err := s.RecordFailure("c1", "boom", 3, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	// (c) Read-modify-write, the form the manager's promotion uses.
	if err := s.UpdateCert("c1", func(c *CertState) error {
		c.NotAfter = time.Now().Add(72 * time.Hour)
		return nil
	}); err != nil {
		t.Fatalf("UpdateCert: %v", err)
	}

	st, err := s.GetCert("c1")
	if err != nil || st == nil {
		t.Fatalf("GetCert: %v (st=%v)", err, st)
	}
	if st.OrphanCleanedAt.IsZero() {
		t.Fatal("an ordinary write to the row erased the orphan-clean mark: the sweep would tear this " +
			"name down again on every pass, forever")
	}
	// The writes themselves still have to land, or the protection would be a different bug.
	if st.ConsecutiveFailures != 3 || st.LastError != "boom" {
		t.Errorf("the failure bookkeeping did not survive: %+v", st)
	}
}

func TestClearOrphanCleanedDropsTheMark(t *testing.T) {
	s := openTestStore(t)
	if err := s.PutCert(&CertState{Name: "c1"}); err != nil {
		t.Fatalf("PutCert: %v", err)
	}
	if _, err := s.MarkOrphanCleaned("c1"); err != nil {
		t.Fatalf("MarkOrphanCleaned: %v", err)
	}
	// Clearing a name that carries no mark is a no-op, not an error: the callers run on every pass.
	if err := s.ClearOrphanCleaned("never-marked"); err != nil {
		t.Fatalf("ClearOrphanCleaned on an unknown name: %v", err)
	}
	if err := s.ClearOrphanCleaned("c1"); err != nil {
		t.Fatalf("ClearOrphanCleaned: %v", err)
	}
	st, err := s.GetCert("c1")
	if err != nil || st == nil {
		t.Fatalf("GetCert: %v (st=%v)", err, st)
	}
	if !st.OrphanCleanedAt.IsZero() {
		t.Errorf("the mark must be gone, still %s: a certificate that is desired again has to be torn "+
			"down again when it leaves", st.OrphanCleanedAt)
	}
	// Marking it again works, so clearing is not a one-way door.
	if marked, err := s.MarkOrphanCleaned("c1"); err != nil || !marked {
		t.Fatalf("MarkOrphanCleaned after a clear = %v, %v; want true, nil", marked, err)
	}
}

// The mark means "the teardown finished", and the store refuses it while the residue the teardown
// deliberately keeps is still there: an order row, or an authorization row whose TXT record could
// not be reclaimed (or is still inside its propagation window, so the record may yet appear). The
// row carries the only clue for locating that record again, so marking over it would strand a stale
// _acme-challenge value -- which poisons every other certificate that writes the same name.
func TestMarkOrphanCleanedRefusesWhileResidueIsLeft(t *testing.T) {
	s := openTestStore(t)
	if err := s.PutCert(&CertState{Name: "c1", NotAfter: time.Now().Add(48 * time.Hour)}); err != nil {
		t.Fatalf("PutCert: %v", err)
	}

	if err := s.PutOrder(&Order{CertName: "c1", OrderURL: "https://acme.example/order/1"}); err != nil {
		t.Fatalf("PutOrder: %v", err)
	}
	if marked, err := s.MarkOrphanCleaned("c1"); err != nil || marked {
		t.Fatalf("MarkOrphanCleaned with an order row left = %v, %v; want false, nil", marked, err)
	}

	if err := s.DeleteOrder("c1"); err != nil {
		t.Fatalf("DeleteOrder: %v", err)
	}
	if err := s.PutAuthorization(&Authorization{
		CertName: "c1", AuthzURL: "https://acme.example/authz/1", Identifier: "example.com",
		TxtName: "_acme-challenge.example.com.", TxtValue: "v", Presented: true,
	}); err != nil {
		t.Fatalf("PutAuthorization: %v", err)
	}
	if marked, err := s.MarkOrphanCleaned("c1"); err != nil || marked {
		t.Fatalf("MarkOrphanCleaned with an authorization row left = %v, %v; want false, nil", marked, err)
	}
	st, err := s.GetCert("c1")
	if err != nil || st == nil {
		t.Fatalf("GetCert: %v (st=%v)", err, st)
	}
	if !st.OrphanCleanedAt.IsZero() {
		t.Fatalf("a refused mark must not be written, got %s", st.OrphanCleanedAt)
	}

	// The record is reclaimed, its row goes, and now the mark is allowed.
	if err := s.DeleteAuthorization("c1", "https://acme.example/authz/1"); err != nil {
		t.Fatalf("DeleteAuthorization: %v", err)
	}
	if marked, err := s.MarkOrphanCleaned("c1"); err != nil || !marked {
		t.Fatalf("MarkOrphanCleaned with the residue gone = %v, %v; want true, nil", marked, err)
	}
}

// The sweep needs every name and the mark in ONE read: a GetCert per name in the loop is exactly the
// per-orphan statement this column exists to remove. This test pins the row set and the ordering --
// the property the sweep relies on to find the orphans without a second query -- and that the read
// does not touch certificate material.
func TestListOrphanRowsCoversEveryCertificateInNameOrder(t *testing.T) {
	s := openTestStore(t)
	for _, name := range []string{"c", "a", "b"} {
		if err := s.PutCert(&CertState{
			Name: name, NotAfter: time.Now().Add(48 * time.Hour), CertPEM: []byte("material"),
		}); err != nil {
			t.Fatalf("PutCert(%s): %v", name, err)
		}
	}
	if _, err := s.MarkOrphanCleaned("b"); err != nil {
		t.Fatalf("MarkOrphanCleaned: %v", err)
	}

	rows, err := s.ListOrphanRows()
	if err != nil {
		t.Fatalf("ListOrphanRows: %v", err)
	}
	var names []string
	for _, r := range rows {
		names = append(names, r.Name)
		if r.Name == "b" && r.OrphanCleanedAt.IsZero() {
			t.Error("the mark must be reported for b")
		}
		if r.Name != "b" && !r.OrphanCleanedAt.IsZero() {
			t.Errorf("%s must come back unmarked, got %s", r.Name, r.OrphanCleanedAt)
		}
	}
	want := []string{"a", "b", "c"}
	if len(names) != len(want) {
		t.Fatalf("ListOrphanRows names = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("ListOrphanRows names = %v, want %v (the sweep's bound and its first-N log lines "+
				"are only stable if the order is)", names, want)
		}
	}
}

// A name that is not in the store at all is not an error: the sweep only marks names it found, and
// the store must not invent a row for one it did not.
func TestMarkOrphanCleanedOnAMissingNameIsNotAnError(t *testing.T) {
	s := openTestStore(t)
	marked, err := s.MarkOrphanCleaned("nobody")
	if err != nil {
		t.Fatalf("MarkOrphanCleaned on a missing name: %v", err)
	}
	if marked {
		t.Error("a missing name cannot have a finished teardown to record")
	}
	names, err := s.ListCertNames()
	if err != nil {
		t.Fatalf("ListCertNames: %v", err)
	}
	if len(names) != 0 {
		t.Errorf("the mark must not create a row, got %v", names)
	}
}

// A database this build created is fully migrated as far as this build is concerned -- the property
// the unlocked open checks (pendingMigrations) and the one an older binary's own migrate() re-checks
// for the columns it knows about. Made explicit here because the orphan-clean column is the newest
// one and a missing schemaColumns entry would silently skip the migration on upgrade.
func TestTheOrphanCleanedColumnIsInTheMigrationList(t *testing.T) {
	found := false
	for _, m := range schemaColumns {
		if m.table == "certificates" && m.column == "orphan_cleaned_at" {
			found = true
			if m.decl != "INTEGER NOT NULL DEFAULT 0" {
				t.Errorf("orphan_cleaned_at decl = %q: it must be NOT NULL with a default, or an "+
					"older database would migrate into a NULL the scanner cannot read", m.decl)
			}
		}
	}
	if !found {
		t.Fatal("certificates.orphan_cleaned_at is missing from schemaColumns: an existing database " +
			"would never gain the column")
	}

	// And a store created from scratch really has it.
	s := openTestStore(t)
	if err := s.PutCert(&CertState{Name: "c1"}); err != nil {
		t.Fatalf("PutCert: %v", err)
	}
	if _, err := s.MarkOrphanCleaned("c1"); err != nil {
		t.Fatalf("MarkOrphanCleaned on a fresh database: %v", err)
	}
	pending, err := s.pendingMigrations()
	if err != nil {
		t.Fatalf("pendingMigrations: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("a fresh database still reports pending migrations: %v", pending)
	}
}
