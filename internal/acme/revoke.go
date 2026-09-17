package acme

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	legoacme "github.com/go-acme/lego/v4/acme"
	"strings"
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
// ErrRevocationNotRecorded marks the failures where NOTHING reached the state store: there is no
// queued request, and no later pass will retry anything. Callers that tell an operator "it is
// recorded and will be retried" must check for it -- on a key compromise, telling someone their
// revocation is queued when it is not is wrong in the unsafe direction.
var ErrRevocationNotRecorded = errors.New("the revocation request was not recorded")

func (m *Manager) RequestRevocation(ctx context.Context, certName string, reason int) error {
	st, err := m.store.GetCert(certName)
	if err != nil {
		return fmt.Errorf("%w: reading the certificate: %w", ErrRevocationNotRecorded, err)
	}
	if st == nil || len(st.CertPEM) == 0 {
		return fmt.Errorf("%w: no certificate material stored for %q, so there is nothing to revoke; "+
			"if the certificate was issued before wecert started archiving it, revoke it at the CA",
			ErrRevocationNotRecorded, certName)
	}

	if _, err := m.RevocationReasonCode(reason); err != nil {
		return fmt.Errorf("%w: %w", ErrRevocationNotRecorded, err)
	}

	if err := m.store.AddRevokeRequest(certName, reason, m.now()); err != nil {
		return fmt.Errorf("%w: %w", ErrRevocationNotRecorded, err)
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

// RetryPendingRevocations attempts every outstanding request. Called once per pass.
//
// A failure is logged and recorded, never fatal to the pass: a certificate that cannot be revoked
// right now must not stop the other certificates from renewing. Every failed attempt is persisted,
// so "how long has this been failing" is answerable, and the request stays outstanding -- which is
// what keeps wecert_revocation_pending non-zero and its alert firing. Being unable to read the list
// at all is counted by the caller instead, as wecert_revocation_query_errors_total.
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

// PendingRevocations reports how many requests are outstanding. The reconciler uses it both as
// the gate for the retry and as the value of wecert_revocation_pending.
//
// The error is returned instead of being folded into a zero count. Zero is a meaningful answer
// here -- "nothing outstanding" -- so a store that cannot be read must not be able to produce it:
// that would turn a database failure into a confident all-clear on the one signal that says a
// certificate which should no longer be trusted still is.
func (m *Manager) PendingRevocations() (int, error) {
	reqs, err := m.store.ListRevokeRequests()
	if err != nil {
		return 0, err
	}
	return len(reqs), nil
}

// isAlreadyRevoked reports whether the CA answered "this certificate is already revoked".
//
// The ACME problem type is the contract (RFC 8555 §6.7 registers alreadyRevoked); lego hands the
// ball back as *acme.ProblemDetails, and an implementation that wrapped it into a plain error still
// carries the type string, so the text is checked as a fallback -- the same belt-and-braces the
// DNSPod error predicate uses.
func isAlreadyRevoked(err error) bool {
	if err == nil {
		return false
	}
	const problemType = "urn:ietf:params:acme:error:alreadyRevoked"
	var prob *legoacme.ProblemDetails
	if errors.As(err, &prob) && prob.Type == problemType {
		return true
	}
	return strings.Contains(err.Error(), problemType)
}

// processRevocation performs one attempt for a recorded request.
//
// ctx is accepted and not threaded into the CA call, because lego's low-level api.Core is
// context-free: there is no ctx-taking RevokeCertificate to pass it to. What bounds the request is
// the ACME HTTP client's own timeout (main builds it with 60s). The consequence is deliberate and
// worth stating: a revocation already in flight when the pass is cancelled still runs to
// completion, because a half-sent revocation is worse than a shutdown that takes another moment.
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
		// "Already revoked" is the CA telling us the desired state is in place. Treating it as
		// retryable left the row outstanding forever: ClearRevokeRequest only runs on success, so
		// wecert_revocation_pending stayed >= 1, the critical WecertRevocationPending alert never
		// cleared, every pass re-attempted, and `wecert -revoke` kept telling the operator of a
		// revoked certificate that the request "will be retried". Reachable without any mistake
		// here -- another client revoking through the console, or a state.db restored from a
		// snapshot taken before the row was cleared, both land on it.
		if isAlreadyRevoked(err) {
			if cerr := m.store.ClearRevokeRequest(certName); cerr != nil {
				m.log.Warn("the CA reports the certificate already revoked, but the request row "+
					"could not be cleared", "cert", certName, "err", cerr)
				return nil
			}
			m.log.Info("the CA reports the certificate already revoked; the request is cleared",
				"cert", certName, "reason", ReasonName(req.Reason))
			return nil
		}
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
