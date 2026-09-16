package acme

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// RevocationReasons are the RFC 5280 CRLReason codes an operator may choose.
//
// Only the four that make sense for a TLS certificate served by a load balancer are offered.
// "unspecified" exists because a CA is allowed to reject a reason code and an operator with no
// better answer should not be blocked from revoking at all.
var RevocationReasons = map[string]int{
	"unspecified":          0,
	"keyCompromise":        1,
	"affiliationChanged":   3,
	"superseded":           4,
	"cessationOfOperation": 5,
}

// ReasonName renders a code for a log line.
func ReasonName(code int) string {
	for name, c := range RevocationReasons {
		if c == code {
			return name
		}
	}
	return fmt.Sprintf("reason-%d", code)
}

// RequestRevocation records that a certificate must be revoked, and tries immediately.
//
// Recording comes first and is a separate step on purpose. Revocation is unbounded in time --
// a leaked key does not stop being leaked because the CA returned a 503 -- so the decision has
// to survive the process. If this only attempted the revoke and reported the error, a
// transient failure would leave the operator believing the certificate was revoked when it was
// not, which is the worst possible outcome for this particular action.
func (m *Manager) RequestRevocation(ctx context.Context, certName string, reason int) error {
	st, err := m.store.GetCert(certName)
	if err != nil {
		return err
	}
	if st == nil || len(st.CertPEM) == 0 {
		return fmt.Errorf("no certificate material stored for %q, so there is nothing to revoke; "+
			"if the certificate was issued before wecert started archiving it, revoke it at the CA", certName)
	}

	if _, err := m.RevocationReasonCode(reason); err != nil {
		return err
	}

	if err := m.store.AddRevokeRequest(certName, reason, m.now()); err != nil {
		return err
	}
	m.log.Error("revocation requested; the request is recorded and will be retried until the CA accepts it",
		"cert", certName, "reason", ReasonName(reason))

	// Attempt now so the common case completes while the operator is watching, but the error
	// is returned for information only: the request is durable either way, and the daemon's
	// next pass retries it.
	if err := m.processRevocation(ctx, certName); err != nil {
		return fmt.Errorf("the CA has not accepted the revocation yet; it is recorded and will be "+
			"retried on every pass: %w", err)
	}
	return nil
}

// RevocationReasonCode validates a reason code.
func (m *Manager) RevocationReasonCode(code int) (int, error) {
	for _, c := range RevocationReasons {
		if c == code {
			return code, nil
		}
	}
	return 0, fmt.Errorf("unknown revocation reason %d; expected one of the RFC 5280 codes this "+
		"program offers (0 unspecified, 1 keyCompromise, 3 affiliationChanged, 4 superseded, "+
		"5 cessationOfOperation)", code)
}

// HasPendingRevocations reports whether any request is outstanding, so a pass can skip the
// query on the overwhelming majority of passes that have none.
func (m *Manager) HasPendingRevocations() bool { return m.PendingRevocations() > 0 }

// RetryPendingRevocations attempts every outstanding request. Called once per pass.
//
// A failure is logged and counted, never fatal to the pass: a certificate that cannot be
// revoked right now must not stop the other certificates from renewing.
func (m *Manager) RetryPendingRevocations(ctx context.Context) {
	reqs, err := m.store.ListRevokeRequests()
	if err != nil {
		m.log.Warn("cannot list pending revocations", "err", err)
		return
	}
	for _, r := range reqs {
		if err := m.processRevocation(ctx, r.CertName); err != nil {
			m.log.Warn("revocation still not accepted by the CA; will retry on the next pass",
				"cert", r.CertName, "reason", ReasonName(r.Reason),
				"attempts", r.Attempts+1, "outstanding", time.Since(r.RequestedAt).Round(time.Minute),
				"err", err)
		}
	}
}

// PendingRevocations reports how many requests are outstanding, for metrics.
func (m *Manager) PendingRevocations() int {
	reqs, err := m.store.ListRevokeRequests()
	if err != nil {
		return 0
	}
	return len(reqs)
}

// processRevocation performs one attempt for a recorded request.
func (m *Manager) processRevocation(ctx context.Context, certName string) error {
	req, err := m.store.GetRevokeRequest(certName)
	if err != nil {
		return err
	}
	if req == nil {
		return nil
	}

	st, err := m.store.GetCert(certName)
	if err != nil {
		return err
	}
	if st == nil || len(st.CertPEM) == 0 {
		// Nothing to revoke with. Clearing the request would lose the operator's decision, so
		// it is left outstanding and reported by PendingRevocations.
		err := errors.New("no stored certificate material to revoke")
		_ = m.store.RecordRevokeAttempt(certName, err, m.now())
		return err
	}

	der, err := leafDER(st.CertPEM)
	if err != nil {
		_ = m.store.RecordRevokeAttempt(certName, err, m.now())
		return err
	}

	if err := m.core.RevokeCertificate(der, req.Reason); err != nil {
		_ = m.store.RecordRevokeAttempt(certName, err, m.now())
		return fmt.Errorf("revoke %s: %w", certName, err)
	}

	if err := m.store.ClearRevokeRequest(certName); err != nil {
		// The CA accepted it; failing to clear the row means one more attempt next pass, which
		// the CA answers with "already revoked" -- harmless, and better than reporting failure
		// for an action that succeeded.
		m.log.Warn("the CA revoked the certificate but the request row could not be cleared; "+
			"one more attempt will be made and the CA will report it as already revoked",
			"cert", certName, "err", err)
		return nil
	}

	m.log.Error("CERTIFICATE REVOKED",
		"cert", certName, "reason", ReasonName(req.Reason),
		"outstandingFor", m.now().Sub(req.RequestedAt).Round(time.Minute))
	_ = ctx
	return nil
}

// leafDER extracts the first certificate's DER bytes from a PEM bundle.
func leafDER(certPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("no PEM block found in the stored certificate")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected a CERTIFICATE block, got %q", block.Type)
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return nil, fmt.Errorf("stored certificate does not parse: %w", err)
	}
	return block.Bytes, nil
}
