package state

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// RevokeRequest is a durable "this certificate must be revoked" decision.
//
// It is durable because revocation is a security action with an unbounded deadline: a leaked
// private key does not stop being leaked because the CA returned a 503. A request that only
// existed as a CLI invocation would be lost on any transient failure, leaving the operator
// believing the certificate was revoked when it was not -- the worst possible outcome for this
// particular action.
type RevokeRequest struct {
	CertName string

	// CertIdentity names the certificate the operator asked to revoke, derived from its material
	// and not from the name: a renewal replaces the material under the same name.
	//
	// Empty means the request predates this column, and the retry then has nothing to compare --
	// it revokes whatever is stored, which is what it did before. See acme.processRevocation.
	CertIdentity string

	// Reason is the RFC 5280 CRLReason code (0 unspecified, 1 keyCompromise, 4 superseded,
	// 5 cessationOfOperation, ...). Stored so the operator's choice survives every retry.
	Reason int

	RequestedAt time.Time
	Attempts    int
	LastError   string

	LastAttemptAt time.Time
}

// AddRevokeRequest records (or refreshes) the intent to revoke a certificate.
//
// Idempotent in the sense that matters: asking again for a certificate already pending keeps
// the original RequestedAt, because "how long has this been outstanding" is the number an
// operator needs, and refreshing it would hide a request that has been failing for a week.
//
// certIdentity is refreshed along with the reason, and the two go together: this call IS the
// operator asking, right now, for the certificate stored under this name now. A retry does not
// come through here, so it keeps targeting the certificate the request was made about -- which is
// the whole point of storing the identity.
//
// When the identity CHANGES, the attempt ledger (attempts, last_error, last_attempt_at) is
// reset with it: those counters describe tries at revoking the OLD material, and carrying them
// onto a new request makes a fresh decision look already-failed -- including pushing it past a
// retry ceiling it has never once hit.
func (s *Store) AddRevokeRequest(certName string, reason int, certIdentity string, now time.Time) error {
	if certName == "" {
		return errors.New("revoke request needs a certificate name")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`
		INSERT INTO revoke_requests (cert_name, reason, cert_identity, requested_at, attempts, last_error, last_attempt_at)
		VALUES (?, ?, ?, ?, 0, '', 0)
		ON CONFLICT(cert_name) DO UPDATE SET
		    reason = excluded.reason,
		    cert_identity = excluded.cert_identity,
		    -- A request naming DIFFERENT material is a new decision: the attempts and the error
		    -- on file describe tries at revoking the old certificate and say nothing about this
		    -- one. Same identity (the operator simply asking again) keeps the ledger as it is.
		    attempts        = CASE WHEN excluded.cert_identity != revoke_requests.cert_identity
		                           THEN 0 ELSE revoke_requests.attempts END,
		    last_error      = CASE WHEN excluded.cert_identity != revoke_requests.cert_identity
		                           THEN '' ELSE revoke_requests.last_error END,
		    last_attempt_at = CASE WHEN excluded.cert_identity != revoke_requests.cert_identity
		                           THEN 0 ELSE revoke_requests.last_attempt_at END`,
		certName, reason, certIdentity, toUnix(now))
	if err != nil {
		return fmt.Errorf("record revoke request for %s: %w", certName, err)
	}
	return nil
}

// ListRevokeRequests returns the outstanding requests, oldest first.
func (s *Store) ListRevokeRequests() ([]*RevokeRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`
		SELECT cert_name, reason, cert_identity, requested_at, attempts, last_error, last_attempt_at
		FROM revoke_requests ORDER BY requested_at`)
	if err != nil {
		return nil, fmt.Errorf("list revoke requests: %w", err)
	}
	defer rows.Close()

	var out []*RevokeRequest
	for rows.Next() {
		var (
			r             RevokeRequest
			requestedAt   int64
			lastAttemptAt int64
		)
		if err := rows.Scan(&r.CertName, &r.Reason, &r.CertIdentity, &requestedAt, &r.Attempts, &r.LastError, &lastAttemptAt); err != nil {
			return nil, fmt.Errorf("scan revoke request: %w", err)
		}
		r.RequestedAt = fromUnix(requestedAt)
		r.LastAttemptAt = fromUnix(lastAttemptAt)
		out = append(out, &r)
	}
	return out, rows.Err()
}

// GetRevokeRequest reads one request, or nil when there is none.
func (s *Store) GetRevokeRequest(certName string) (*RevokeRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var (
		r             RevokeRequest
		requestedAt   int64
		lastAttemptAt int64
	)
	err := s.db.QueryRow(`
		SELECT cert_name, reason, cert_identity, requested_at, attempts, last_error, last_attempt_at
		FROM revoke_requests WHERE cert_name = ?`, certName).
		Scan(&r.CertName, &r.Reason, &r.CertIdentity, &requestedAt, &r.Attempts, &r.LastError, &lastAttemptAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("read revoke request for %s: %w", certName, err)
	}
	r.RequestedAt = fromUnix(requestedAt)
	r.LastAttemptAt = fromUnix(lastAttemptAt)
	return &r, nil
}

// RecordRevokeAttempt counts a failed attempt and remembers why.
//
// The error is kept so an operator can see whether they are waiting on a transient condition
// or on something that will never succeed (a CA that refuses the reason code, say) -- the two
// call for opposite responses.
//
// A name with no outstanding request is an error, not a silent no-op: an UPDATE that matches
// nothing reports success otherwise, and the caller would believe an attempt was recorded when
// there is no request to record it against.
func (s *Store) RecordRevokeAttempt(certName string, attemptErr error, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	msg := ""
	if attemptErr != nil {
		// Bounded like every other last_error writer in this package: lego hands back the CA's
		// body verbatim, and one huge HTML error page in every attempt row is how a state file
		// grows without bound.
		msg = truncate(attemptErr.Error(), maxLastErrorBytes)
	}
	res, err := s.db.Exec(`
		UPDATE revoke_requests
		SET attempts = attempts + 1, last_error = ?, last_attempt_at = ?
		WHERE cert_name = ?`, msg, toUnix(now), certName)
	if err != nil {
		return fmt.Errorf("record revoke attempt for %s: %w", certName, err)
	}
	// An UPDATE against a name that has no row matches nothing and reports success: the attempt
	// would be counted nowhere, which reads as "the request is being tracked" when there is no
	// request at all.
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("record revoke attempt for %s: %w", certName, err)
	} else if n == 0 {
		return fmt.Errorf("record revoke attempt for %s: no such revoke request", certName)
	}
	return nil
}

// ClearRevokeRequest forgets a request that the CA has accepted.
func (s *Store) ClearRevokeRequest(certName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.db.Exec(`DELETE FROM revoke_requests WHERE cert_name = ?`, certName); err != nil {
		return fmt.Errorf("clear revoke request for %s: %w", certName, err)
	}
	return nil
}
