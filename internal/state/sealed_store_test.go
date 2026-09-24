package state

import (
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
