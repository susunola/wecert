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
		t.Fatalf("DeployConfirmed 未恢复: %+v", got)
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
		t.Fatal("DeployConfirmed 应为 false")
	}
}

func TestDeployConfirmedMigratesOnOldSchema(t *testing.T) {
	s := openTestStore(t)
	got, err := s.GetCert("fresh")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("不存在的证书应返回 nil: %+v", got)
	}
	if err := s.PutCert(&CertState{Name: "fresh"}); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetCert("fresh")
	if err != nil {
		t.Fatal(err)
	}
	if got.DeployConfirmed {
		t.Fatal("新行 DeployConfirmed 默认应为 false")
	}
}
