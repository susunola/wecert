package state

import (
	"context"
	"path/filepath"
	"testing"
)

func TestOpenSealedEncryptsAccountKeysAndRejectsWrongMaster(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := OpenSealed(path, []byte("master-one"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutAccount(&Account{Directory: "https://acme.example/d", KID: "kid", PrivateKeyPEM: []byte("PRIVATE KEY")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	good, err := OpenSealed(path, []byte("master-one"))
	if err != nil {
		t.Fatal(err)
	}
	account, err := good.GetAccount("https://acme.example/d")
	_ = good.Close()
	if err != nil || string(account.PrivateKeyPEM) != "PRIVATE KEY" {
		t.Fatalf("decrypt = %#v, %v", account, err)
	}

	bad, err := OpenSealed(path, []byte("master-two"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.GetAccount("https://acme.example/d"); err == nil {
		t.Fatal("wrong master key must be rejected")
	}
	_ = bad.Close()
}

func TestOpenSealedEncryptsTransactionalCertificateWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := OpenSealed(path, []byte("master"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.WithTx(context.Background(), func(tx *Tx) error { return tx.PutCert(&CertState{Name: "tx", KeyPEM: []byte("TX KEY")}) }); err != nil {
		t.Fatal(err)
	}
	c, err := s.GetCert("tx")
	if err != nil || string(c.KeyPEM) != "TX KEY" {
		t.Fatalf("cert = %#v, %v", c, err)
	}
	_ = s.Close()
}

func TestOpenSealedRoundTripsRetiredCertificateMaterial(t *testing.T) {
	s, err := OpenSealed(filepath.Join(t.TempDir(), "state.db"), []byte("master"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.AddRetiredCert("old-id", "www", []byte("OLD CERT"), []byte("OLD KEY")); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListRetiredCertMaterial("www")
	if err != nil || len(rows) != 1 || string(rows[0].CertPEM) != "OLD CERT" || string(rows[0].KeyPEM) != "OLD KEY" {
		t.Fatalf("retired = %#v, %v", rows, err)
	}
}

func TestOpenSealedMigratesExistingPlaintextState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	plain, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := plain.PutAccount(&Account{Directory: "https://acme.example/d", PrivateKeyPEM: []byte("OLD ACCOUNT")}); err != nil {
		t.Fatal(err)
	}
	if err := plain.PutOrder(&Order{CertName: "c", KeyPEM: []byte("OLD ORDER")}); err != nil {
		t.Fatal(err)
	}
	if err := plain.PutCert(&CertState{Name: "c", CertPEM: []byte("OLD CERT"), KeyPEM: []byte("OLD KEY")}); err != nil {
		t.Fatal(err)
	}
	if err := plain.Close(); err != nil {
		t.Fatal(err)
	}

	sealed, err := OpenSealed(path, []byte("master"))
	if err != nil {
		t.Fatal(err)
	}
	defer sealed.Close()
	a, _ := sealed.GetAccount("https://acme.example/d")
	o, _ := sealed.GetOrder("c")
	c, _ := sealed.GetCert("c")
	if string(a.PrivateKeyPEM) != "OLD ACCOUNT" || string(o.KeyPEM) != "OLD ORDER" || string(c.CertPEM) != "OLD CERT" || string(c.KeyPEM) != "OLD KEY" {
		t.Fatal("migration did not preserve plaintext material")
	}
}

func TestOpenSealedRoundTripsOrderAndCertificateMaterial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := OpenSealed(path, []byte("master"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutOrder(&Order{CertName: "www", OrderURL: "order", KeyPEM: []byte("ORDER KEY")}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutCert(&CertState{Name: "www", CertPEM: []byte("CERT"), KeyPEM: []byte("CERT KEY")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = OpenSealed(path, []byte("master"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	o, err := s.GetOrder("www")
	if err != nil || string(o.KeyPEM) != "ORDER KEY" {
		t.Fatalf("order = %#v, %v", o, err)
	}
	c, err := s.GetCert("www")
	if err != nil || string(c.CertPEM) != "CERT" || string(c.KeyPEM) != "CERT KEY" {
		t.Fatalf("cert = %#v, %v", c, err)
	}
}
