package state

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A transaction that fails must leave nothing behind.
//
// This is the property the renewal epilogue depends on: it promotes the new certificate, retires
// the old one and discards the order in one unit, and a half-applied version of that is not
// repairable by a later pass -- promote-without-retire leaks a cloud certificate that nothing will
// ever delete, retire-without-promote marks the certificate that is still serving for deletion.
func TestWithTxRollsBackEverythingOnError(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	// A certificate that exists before the transaction, to prove the rollback restores it.
	before := &CertState{Name: "c", NotAfter: time.Unix(1000, 0), CertPEM: []byte("old"), KeyPEM: []byte("oldkey")}
	if err := s.PutCert(before); err != nil {
		t.Fatal(err)
	}

	sentinel := errors.New("the third statement fails")
	err := s.WithTx(ctx, func(tx *Tx) error {
		if err := tx.PutCert(&CertState{
			Name: "c", NotAfter: time.Unix(2000, 0), CertPEM: []byte("new"), KeyPEM: []byte("newkey"),
		}); err != nil {
			return err
		}
		if err := tx.AddRetiredCert("ap-old", "c", []byte("old"), []byte("oldkey")); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("the caller's error must be returned unchanged, got %v", err)
	}

	got, err := s.GetCert("c")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.CertPEM) != "old" || !got.NotAfter.Equal(time.Unix(1000, 0)) {
		t.Errorf("the certificate was modified by a transaction that rolled back: %+v", got)
	}
	retired, err := s.ListRetiredCertsBefore(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(retired) != 0 {
		t.Errorf("a rolled-back transaction left a reclaim record behind: %+v. That record would "+
			"have the reaper delete a certificate the state says is still live", retired)
	}
}

// A panic inside the transaction must roll back too, not commit half of it.
//
// The epilogue runs on the path where a certificate has just gone live; a panic there is exactly
// when a half-written state would be most damaging.
func TestWithTxRollsBackOnPanic(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("the test needs the panic to propagate out of WithTx")
			}
		}()
		_ = s.WithTx(ctx, func(tx *Tx) error {
			if err := tx.PutCert(&CertState{Name: "p", CertPEM: []byte("half")}); err != nil {
				return err
			}
			panic("something in the epilogue panicked")
		})
	}()

	got, err := s.GetCert("p")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("a panicking transaction committed its first statement: %+v", got)
	}
}

// Everything committed together is visible together.
func TestWithTxCommitsAllOrNothing(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	err := s.WithTx(ctx, func(tx *Tx) error {
		if err := tx.PutCert(&CertState{Name: "c", CertPEM: []byte("new"), NotAfter: time.Unix(3000, 0)}); err != nil {
			return err
		}
		if err := tx.AddRetiredCert("ap-old", "c", []byte("old"), []byte("oldkey")); err != nil {
			return err
		}
		if err := tx.DeleteOrder("c"); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatalf("a transaction with no failing statement must commit: %v", err)
	}

	if got, _ := s.GetCert("c"); got == nil || string(got.CertPEM) != "new" {
		t.Errorf("the promoted certificate is missing: %+v", got)
	}
	if retired, _ := s.ListRetiredCertsBefore(time.Now().Add(time.Hour)); len(retired) != 1 || retired[0].CertID != "ap-old" {
		t.Errorf("the retired certificate is missing: %+v", retired)
	}
}

// The store's own methods must still work while nobody holds a transaction, and a Tx must not
// deadlock by trying to take the store's mutex again -- WithTx holds it for the whole call.
func TestStoreMethodsStillWorkOutsideTransactions(t *testing.T) {
	s := openTestStore(t)
	if err := s.PutCert(&CertState{Name: "plain", CertPEM: []byte("x")}); err != nil {
		t.Fatalf("a plain write after the transaction support landed must still work: %v", err)
	}
	if err := s.WithTx(context.Background(), func(tx *Tx) error {
		return tx.PutCert(&CertState{Name: "in-tx", CertPEM: []byte("y")})
	}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetCert("in-tx"); got == nil {
		t.Error("a write inside a committed transaction is not visible afterwards")
	}
}

// The transaction really is BEGIN IMMEDIATE.
//
// tx.go's reasoning depends on it: in WAL, a deferred transaction that reads before it writes can
// fail at COMMIT with SQLITE_BUSY after doing all its work, which reads like a commit bug rather
// than a lock conflict, and taking the write lock at BEGIN is what turns that into a wait. The
// claim is about modernc's driver honouring `_txlock=immediate` in the DSN, so it is checked rather
// than assumed: with IMMEDIATE a transaction holds the write lock from the moment it opens, so a
// second connection cannot write even while the first has written nothing.
func TestTransactionsAreImmediate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// A short busy timeout on the second connection, so the answer arrives quickly instead of
	// after the production five seconds.
	other, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(100)")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()

	release := make(chan struct{})
	opened := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = s.WithTx(context.Background(), func(*Tx) error {
			close(opened)
			<-release // hold it open, having written nothing at all
			return nil
		})
	}()
	<-opened

	_, writeErr := other.Exec(
		`INSERT INTO retired_certificates (cert_id, cert_name, retired_at) VALUES ('x','x',1)`)
	close(release)
	<-done

	if writeErr == nil {
		t.Fatal("a second connection wrote while this transaction was open and had written nothing, " +
			"so the BEGIN is deferred: `_txlock=immediate` is not reaching the driver, and the " +
			"comment in tx.go is describing behaviour this program does not have")
	}
	// It has to fail for the right reason. A first version of this test accepted any error, and a
	// mutated DSN that pointed the second connection at a bogus file satisfied it with "no such
	// table" -- a passing test that proved nothing.
	if !strings.Contains(writeErr.Error(), "locked") && !strings.Contains(writeErr.Error(), "BUSY") {
		t.Fatalf("the second writer was refused, but not because the write lock was held: %v. "+
			"That is not the behaviour this test exists to pin.", writeErr)
	}
}
