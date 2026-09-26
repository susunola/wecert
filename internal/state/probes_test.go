package state

import (
	"testing"
	"time"
)

func TestProbeSamplesKeepOnlyTheLastVerdict(t *testing.T) {
	s := newStore(t)
	defer s.Close()
	first := time.Date(2026, 9, 24, 1, 2, 3, 0, time.UTC)
	if err := s.PutProbeSample(ProbeSample{
		CertName: "www", Host: "www.example.com", Match: true, Trusted: true,
		NotAfter: first.Add(24 * time.Hour), ObservedAt: first,
	}); err != nil {
		t.Fatal(err)
	}
	second := first.Add(time.Hour)
	if err := s.PutProbeSample(ProbeSample{
		CertName: "www", Host: "www.example.com", ProblemKind: "unreachable", ObservedAt: second,
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListProbeSamples("www")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Match || rows[0].Trusted || !rows[0].NotAfter.IsZero() || rows[0].ProblemKind != "unreachable" || !rows[0].ObservedAt.Equal(second) {
		t.Fatalf("persisted probe row = %+v, want the last unreachable verdict", rows)
	}
}

// A certificate that left the fleet takes its rows with it.
//
// The teardown of an orphan drops the per-certificate metric series and makes the prober forget the
// hosts; the persisted rows describe the same endpoints and have the same "nothing will ever look
// at this again" property, so they are dropped in the same place. The alternative is one row per
// certificate/host pair for every name the deployment has ever had.
func TestDeleteProbeSamplesRemovesOnlyThatCertificatesRows(t *testing.T) {
	s := newStore(t)
	defer s.Close()
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	for _, sample := range []ProbeSample{
		{CertName: "gone", Host: "gone.example.com", Match: true, ObservedAt: now},
		{CertName: "gone", Host: "www.gone.example.com", Match: false, ProblemKind: "unreachable", ObservedAt: now},
		{CertName: "kept", Host: "kept.example.com", Match: true, ObservedAt: now},
	} {
		if err := s.PutProbeSample(sample); err != nil {
			t.Fatal(err)
		}
	}

	removed, err := s.DeleteProbeSamples("gone")
	if err != nil {
		t.Fatalf("DeleteProbeSamples: %v", err)
	}
	if removed != 2 {
		t.Errorf("removed %d rows, want the two of the departed certificate", removed)
	}
	if rows, err := s.ListProbeSamples("gone"); err != nil || len(rows) != 0 {
		t.Errorf("departed certificate still has %d row(s) (err %v)", len(rows), err)
	}
	// The other certificate's evidence is not collateral: a shared name would make this wrong in
	// the direction that loses a live certificate's only diagnostic history.
	rows, err := s.ListProbeSamples("kept")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Host != "kept.example.com" {
		t.Errorf("kept certificate rows = %+v, want its own single row", rows)
	}

	// Idempotent: the teardown may run again after a failed attempt.
	removed, err = s.DeleteProbeSamples("gone")
	if err != nil || removed != 0 {
		t.Errorf("second delete = %d rows, err %v; want 0 and no error", removed, err)
	}
	if _, err := s.DeleteProbeSamples(""); err == nil {
		t.Error("an empty certificate name must be refused rather than deleting nothing silently")
	}
}
