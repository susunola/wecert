package state

import "testing"

func TestSealerBindsCiphertextToItsField(t *testing.T) {
	s, err := newSealer([]byte("master"))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := s.seal([]byte("private-key"), []byte("accounts/key"))
	if err != nil {
		t.Fatal(err)
	}
	if string(ciphertext) == "private-key" {
		t.Fatal("plaintext leaked")
	}
	if _, err := s.open(ciphertext, []byte("orders/key")); err == nil {
		t.Fatal("wrong field must not decrypt")
	}
	plain, err := s.open(ciphertext, []byte("accounts/key"))
	if err != nil || string(plain) != "private-key" {
		t.Fatalf("open = %q, %v", plain, err)
	}
}
