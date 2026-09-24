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
