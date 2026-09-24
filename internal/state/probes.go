package state

import (
	"fmt"
	"time"
)

// ProbeSample is durable, read-only diagnostic evidence from one TLS probe.
// It intentionally has no certificate material, remote address, or chain text:
// those are useful only in the immediate log and can grow without bound.
type ProbeSample struct {
	CertName    string
	Host        string
	Match       bool
	Trusted     bool
	NotAfter    time.Time
	ProblemKind string
	ObservedAt  time.Time
}

// PutProbeSample replaces the last result for a certificate/host pair.
func (s *Store) PutProbeSample(sample ProbeSample) error {
	if sample.CertName == "" || sample.Host == "" {
		return fmt.Errorf("probe sample needs certificate name and host")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`
		INSERT INTO probe_samples (cert_name, host, match, trusted, not_after, problem_kind, observed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(cert_name, host) DO UPDATE SET
		    match = excluded.match, trusted = excluded.trusted, not_after = excluded.not_after,
		    problem_kind = excluded.problem_kind, observed_at = excluded.observed_at`,
		sample.CertName, sample.Host, boolInt(sample.Match), boolInt(sample.Trusted),
		toUnix(sample.NotAfter), truncate(sample.ProblemKind, 128), toUnix(sample.ObservedAt))
	if err != nil {
		return fmt.Errorf("store probe sample for %s/%s: %w", sample.CertName, sample.Host, err)
	}
	return nil
}

// ListProbeSamples returns the newest known verdict per host, in host order.
func (s *Store) ListProbeSamples(certName string) ([]ProbeSample, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`
		SELECT cert_name, host, match, trusted, not_after, problem_kind, observed_at
		FROM probe_samples WHERE cert_name = ? ORDER BY host`, certName)
	if err != nil {
		return nil, fmt.Errorf("list probe samples for %s: %w", certName, err)
	}
	defer rows.Close()
	var out []ProbeSample
	for rows.Next() {
		var row ProbeSample
		var match, trusted int
		var notAfter, observedAt int64
		if err := rows.Scan(&row.CertName, &row.Host, &match, &trusted, &notAfter, &row.ProblemKind, &observedAt); err != nil {
			return nil, fmt.Errorf("scan probe sample: %w", err)
		}
		row.Match, row.Trusted = match != 0, trusted != 0
		row.NotAfter, row.ObservedAt = fromUnix(notAfter), fromUnix(observedAt)
		out = append(out, row)
	}
	return out, rows.Err()
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
