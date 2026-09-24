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
