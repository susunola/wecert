package state

import "testing"

func TestDeployConfirmedRoundTrip(t *testing.T) {
	s := openTestStore(t)

	if err := s.PutCert(&CertState{Name: "example-com", DeployedCertID: "apXXXX", DeployConfirmed: true}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetCert("example-com")
	if err != nil {
		t.Fatal(err)
	}
	if !got.DeployConfirmed || got.DeployedCertID != "apXXXX" {
		t.Fatalf("DeployConfirmed was not restored: %+v", got)
	}

	got.DeployConfirmed = false
	if err := s.PutCert(got); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetCert("example-com")
	if err != nil {
		t.Fatal(err)
	}
	if got.DeployConfirmed {
		t.Fatal("DeployConfirmed should be false")
	}
}

func TestDeployConfirmedMigratesOnOldSchema(t *testing.T) {
	s := openTestStore(t)
	got, err := s.GetCert("fresh")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("a missing certificate should return nil: %+v", got)
	}
	if err := s.PutCert(&CertState{Name: "fresh"}); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetCert("fresh")
	if err != nil {
		t.Fatal(err)
	}
	if got.DeployConfirmed {
		t.Fatal("DeployConfirmed on a new row should default to false")
	}
}
