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

	"github.com/susunola/wecert/internal/state"
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

// RequestRevocation records the decision and then tries once.
func (m *Manager) RequestRevocation(ctx context.Context, certName string, reason int) error {
	if err := m.RecordRevocation(certName, reason); err != nil {
		return err
	}

	// Attempt now so the common case completes while the operator is watching, but the error
	// is returned for information only: the request is durable either way, and the daemon's
	// next pass retries it.
	if err := m.processRevocation(ctx, certName); err != nil {
		return fmt.Errorf("the CA has not accepted the revocation yet; it is recorded and will be "+
			"retried on every pass: %w", err)
	}
	return nil
}

// RecordRevocation writes the operator's decision to the state store, and touches no network.
//
// It is separate from RequestRevocation because the order matters when the CA is unreachable, which
// is exactly when an operator is most likely to be revoking something: the CLI used to prepare the
// ACME account BEFORE calling in here, so a CA that was down (or a directory that could not be read)
// meant the run failed with nothing recorded, no retry, and wecert_revocation_pending at 0 -- while
// the documentation promises the decision is durable whatever the CA does. A leaked key does not stop
// being leaked because the CA returned a 503.
func (m *Manager) RecordRevocation(certName string, reason int) error {
	st, err := m.store.GetCert(certName)
	if err != nil {
		return fmt.Errorf("%w: reading the certificate: %w", ErrRevocationNotRecorded, err)
	}
	if st == nil || len(st.CertPEM) == 0 {
		return fmt.Errorf("%w: no certificate material stored for %q, so there is nothing to revoke; "+
			"if the certificate was issued before wecert started archiving it, revoke it at the CA",
			ErrRevocationNotRecorded, certName)
	}

	if _, err := RevocationReasonCode(reason); err != nil {
		return fmt.Errorf("%w: %w", ErrRevocationNotRecorded, err)
	}

	// The identity of the certificate being revoked, recorded with the request. A retry can be
	// days later, and a renewal in between replaces the material stored under this name -- see
	// processRevocation for what the retry does with it.
	identity := ""
	if leaf, err := leafCertificate(st.CertPEM); err == nil {
		identity = certIdentity(leaf)
		// Asking again after a renewal is a new decision about a different certificate, and the
		// upsert below REPLACES the outstanding request rather than adding to it -- there is one row
		// per certificate name, and AddRevokeRequest overwrites its identity.
		//
		// The warning used to say the previous certificate "is revoked only if its request is still
		// outstanding", which reads as "it may still be revoked". It will not be: from the statement
		// below on, the row names the certificate stored now, so every later retry revokes that one
		// and the identity the operator was worried about is referenced nowhere. On a key compromise
		// that is the worst possible reading -- the run then logs "CERTIFICATE REVOKED" for the
		// healthy replacement while the compromised key stays trusted -- so the sentence says the
		// consequence and what to do about it instead.
		if prev, perr := m.store.GetRevokeRequest(certName); perr == nil && prev != nil &&
			prev.CertIdentity != "" && prev.CertIdentity != identity {
			m.log.Warn("an outstanding revocation request for this name targets a DIFFERENT "+
				"certificate than the one stored now. This request replaces it (one row per name), so "+
				"the certificate that was targeted before will NOT be revoked by wecert: revoke it in "+
				"the CA console with the material you still have, or restore that material and revoke "+
				"it before renewing",
				"cert", certName, "outstanding", prev.CertIdentity, "now", identity,
				"wasOutstandingSince", prev.RequestedAt)
		}
	} else {
		// Material that does not parse cannot be identified. Recording the request anyway keeps
		// the operator's decision (the alternative is telling them nothing was recorded, for a
		// request that is in fact queued), and the empty identity makes the retry fall back to
		// revoking the stored material, which is what this did before identities existed.
		m.log.Warn("cannot identify the stored certificate, so the revocation request will not be "+
			"able to tell later whether it was replaced in the meantime", "cert", certName, "err", err)
	}

	if err := m.store.AddRevokeRequest(certName, reason, identity, m.now()); err != nil {
		return fmt.Errorf("%w: %w", ErrRevocationNotRecorded, err)
	}
	m.log.Error("revocation requested; the request is recorded and will be retried until the CA accepts it",
		"cert", certName, "reason", ReasonName(reason))
	return nil
}

// AttemptRecordedRevocation performs one attempt for a request that is already in the store.
//
// The CLI needs this because EnsureAccount -- the step that reads the CA directory -- has to happen
// after the decision is durable (see RecordRevocation), so it builds the manager twice: once with no
// CA core at all to record, and once with the account to attempt.
func (m *Manager) AttemptRecordedRevocation(ctx context.Context, certName string) error {
	return m.processRevocation(ctx, certName)
}

// RevocationReasonCode validates a reason code.
func RevocationReasonCode(code int) (int, error) {
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
	// A coreless manager (the CLI records revocations with one while the CA is unreachable; see
	// RecordRevocation) cannot attempt anything. Say so once for the pass rather than once per
	// request, each of which would read as a CA refusal.
	if m.core == nil {
		if len(reqs) > 0 {
			m.log.Warn("cannot attempt revocations: this manager has no ACME core; the requests stay outstanding",
				"pending", len(reqs))
		}
		return
	}
	for _, r := range reqs {
		if err := m.processRevocation(ctx, r.CertName); err != nil {
			m.log.Warn("revocation still not accepted by the CA; will retry on the next pass",
				"cert", r.CertName, "reason", ReasonName(r.Reason),
				"attempts", r.Attempts+1, "outstanding", m.now().Sub(r.RequestedAt).Round(time.Minute),
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

	// Attempting the revocation needs the CA, and a manager without a core is a real
	// configuration: the CLI builds one on purpose to record the decision while the CA is
	// unreachable (see RecordRevocation). RevokeCertificate sits on that interface, so without
	// this guard the attempt is a nil-interface panic instead of an error the caller can report
	// -- and the request must stay outstanding either way.
	if m.core == nil {
		return errors.New("cannot attempt the revocation: this manager has no ACME core")
	}

	der, err := m.revocationMaterial(certName, req)
	if err != nil {
		// Clearing the request would lose the operator's decision, so it is left outstanding and
		// reported by PendingRevocations.
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

// revocationMaterial decides which certificate bytes a request must send.
//
// Revoking the certificate stored *now* is only correct while it is still the certificate the
// request was made about. A renewal replaces it, and reconcile retries revocations after the
// certificate loop -- so the same pass can install a new certificate and then revoke it, while the
// compromised one stays valid and the request row is cleared as a success. That is the exact
// opposite of what was asked for, so the identity recorded with the request decides.
func (m *Manager) revocationMaterial(certName string, req *state.RevokeRequest) ([]byte, error) {
	st, err := m.store.GetCert(certName)
	if err != nil {
		return nil, err
	}

	var stored *x509.Certificate
	if st != nil && len(st.CertPEM) > 0 {
		stored, err = leafCertificate(st.CertPEM)
		if err != nil {
			return nil, err
		}
	}

	switch {
	case stored == nil:
		// No usable material under the name (never issued, or the row holds none). The archive is
		// then the only way to honour the request, and without an identity there is nothing to
		// look for and nothing to send.
		if req.CertIdentity == "" {
			return nil, errors.New("no stored certificate material to revoke")
		}
		return m.archivedDER(certName, req.CertIdentity)
	case req.CertIdentity == "":
		// Recorded before the identity was stored. There is nothing to compare against, so the
		// material at hand is revoked -- the pre-existing behaviour -- and the gap is stated
		// rather than hidden.
		m.log.Warn("this revocation request carries no certificate identity, so the certificate "+
			"stored now is revoked whichever one that is", "cert", certName)
		return stored.Raw, nil
	case certIdentity(stored) == req.CertIdentity:
		// The ordinary case: the certificate to revoke is still the stored one.
		return stored.Raw, nil
	default:
		archived, aerr := m.archivedDER(certName, req.CertIdentity)
		if aerr != nil {
			return nil, aerr
		}
		m.log.Warn("the certificate stored for this name is not the one this request targets, so "+
			"the archived copy is revoked instead of the live certificate",
			"cert", certName, "requested", req.CertIdentity, "stored", certIdentity(stored))
		return archived, nil
	}
}

// leafCertificate parses the first certificate of a PEM bundle.
//
// A revocation is about the leaf: the intermediates in the bundle are the CA's, not something this
// program may ask to revoke.
func leafCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("no PEM block found in the stored certificate")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected a CERTIFICATE block, got %q", block.Type)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("stored certificate does not parse: %w", err)
	}
	return leaf, nil
}

// certIdentity names a certificate for the revocation bookkeeping.
//
// It is the ARI certID -- base64url(AKI keyIdentifier) "." base64url(DER serial), RFC 9773
// section 4.1 -- because that is already this codebase's answer to "which certificate is this",
// and it is derived from the certificate itself rather than from anything this program stores
// beside it. A leaf without an Authority Key Identifier falls back to its serial, which still
// tells a renewal apart; both forms are produced here, so the stored value and the compared value
// can never disagree about their spelling.
func certIdentity(leaf *x509.Certificate) string {
	if id, err := CertID(leaf); err == nil {
		return id
	}
	return "serial:" + strings.ToUpper(leaf.SerialNumber.Text(16))
}

// archivedDER finds the retired copy of the certificate a revocation request targets.
//
// The request is not abandoned just because the material under the name changed: the certificate
// the operator asked about is the one that must stop being trusted (the reason code is usually
// keyCompromise), and wecert deliberately keeps retired material for rollback. Revoking an
// archived certificate works because the ACME revocation is signed with the ACCOUNT key -- lego's
// api.Core builds every JWS from the account's kid and private key, not from the certificate's own
// key -- so it does not matter that the private key that served it is no longer in use.
//
// When the archive no longer holds it (retention reclaims retired rows, and their material with
// them) there is nothing to send and nothing that can be done from here, so the error says exactly
// that and the request stays outstanding, keeping wecert_revocation_pending up until someone acts.
func (m *Manager) archivedDER(certName, identity string) ([]byte, error) {
	cands, err := m.store.ListRetiredCertMaterial(certName)
	if err != nil {
		return nil, err
	}
	for _, c := range cands {
		leaf, err := leafCertificate(c.CertPEM)
		if err != nil {
			// A retired row whose material does not parse cannot be the certificate asked about,
			// and the operator's own row is the one worth reporting on.
			continue
		}
		if certIdentity(leaf) == identity {
			return leaf.Raw, nil
		}
	}
	return nil, fmt.Errorf("the certificate this request targets (%s) is not the one stored for %q "+
		"and no archived copy of it is held: it has to be revoked at the CA", identity, certName)
}
