// Package state is wecert's persistence layer.
//
// The existence of this layer is itself a requirement: Let's Encrypt explicitly
// names the most common way people hit rate limits -- "deleting the ACME client's
// configuration data on every deploy". Losing the order URL makes a restarted
// process place a fresh order, walking straight into
// "5 certificates per exact set of identifiers / 7 days".
//
// So: account key, order URL, ARI window, and Tencent Cloud CertId all hit disk.
package state

import (
	"fmt"
	_ "modernc.org/sqlite"
	"time"
)

// Per-table CRUD, split out of state.go so one table lives in one file.
// Same package: every method is still on Store.

func (s *Store) AddRetiredCert(certID, certName string, certPEM, keyPEM []byte) error {
	if certID == "" {
		// A row with no id is one the reaper can never delete: Delete("") fails every round and the
		// slot is held forever, which is the opposite of what a reclaim list is for. The only
		// caller that could produce it guards against an empty id itself; this is the second line.
		return fmt.Errorf("refusing to queue an empty certificate id for reclaim under %q", certName)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sealer != nil {
		var err error
		if len(certPEM) > 0 {
			certPEM, err = s.sealer.seal(certPEM, []byte("retired_certificates/cert_pem/"+certID))
			if err != nil {
				return fmt.Errorf("seal retired certificate material: %w", err)
			}
		}
		if len(keyPEM) > 0 {
			keyPEM, err = s.sealer.seal(keyPEM, []byte("retired_certificates/key_pem/"+certID))
			if err != nil {
				return fmt.Errorf("seal retired certificate key: %w", err)
			}
		}
	}
	return addRetiredCertExec(s.db, certID, certName, certPEM, keyPEM)
}

func addRetiredCertExec(e execer, certID, certName string, certPEM, keyPEM []byte) error {
	_, err := e.Exec(`
		INSERT INTO retired_certificates (cert_id, cert_name, retired_at, cert_pem, key_pem)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(cert_id) DO UPDATE SET
		    -- The first writer may have had nothing to archive. The orphan path records a
		    -- certificate it merely uploaded, with NULL material; the retirement path records the
		    -- one that was actually serving, with the fullchain and key. DO NOTHING let whichever
		    -- arrived first win, so a row could keep two NULLs and the documented manual rollback
		    -- (docs/recovery.md) had nothing to restore. COALESCE keeps real material from being
		    -- overwritten by a later empty write, and lets it be filled in when the empty write
		    -- came first.
		    cert_pem = COALESCE(EXCLUDED.cert_pem, retired_certificates.cert_pem),
		    key_pem  = COALESCE(EXCLUDED.key_pem,  retired_certificates.key_pem),
		    -- The clock restarts on the write that actually retires the certificate. Without
		    -- this a row first written by the orphan path (which records a certificate it merely
		    -- uploaded, with no material) kept the ORPHAN's timestamp when the same cert_id was
		    -- later retired with the fullchain and key: ReapRetired, which reaps on retired_at,
		    -- would then delete the cloud copy and the freshly archived rollback material on the
		    -- earlier clock -- and before the rebind it asks to delete a certificate that may
		    -- still be serving, refused only by the cloud-side binding check.
		    retired_at = EXCLUDED.retired_at`,
		certID, certName, time.Now().Unix(), certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("add retired cert %s: %w", certID, err)
	}
	return nil
}

// ListRetiredCertsBefore lists certificates retired before cutoff, for reclamation.
func (s *Store) ListRetiredCertsBefore(cutoff time.Time) ([]*RetiredCert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`
		SELECT cert_id, cert_name, retired_at, cert_pem, key_pem
		FROM retired_certificates WHERE retired_at < ?`,
		cutoff.Unix())
	if err != nil {
		return nil, fmt.Errorf("list retired certs: %w", err)
	}
	defer rows.Close()

	var out []*RetiredCert
	for rows.Next() {
		r := &RetiredCert{}
		var retiredAt int64
		if err := rows.Scan(&r.CertID, &r.CertName, &retiredAt, &r.CertPEM, &r.KeyPEM); err != nil {
			return nil, fmt.Errorf("scan retired cert: %w", err)
		}
		if err := s.openRetiredMaterial(r); err != nil {
			return nil, err
		}
		r.RetiredAt = fromUnix(retiredAt)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListRetiredCertMaterial returns the archived certificate material of every retired certificate
// recorded under one name, newest first.
//
// Rows without material are skipped: the orphan path records a certificate wecert merely uploaded
// and never held a copy of, and an empty blob would look like a usable (empty) certificate. What
// this answers is "is the certificate the operator asked to revoke still here somewhere", which is
// how a revocation request that outlives its renewal can still be honoured.
func (s *Store) ListRetiredCertMaterial(certName string) ([]*RetiredCert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`
		SELECT cert_id, cert_name, retired_at, cert_pem, key_pem
		FROM retired_certificates
		WHERE cert_name = ? AND cert_pem IS NOT NULL
		ORDER BY retired_at DESC`, certName)
	if err != nil {
		return nil, fmt.Errorf("list archived material for %s: %w", certName, err)
	}
	defer rows.Close()

	var out []*RetiredCert
	for rows.Next() {
		r := &RetiredCert{}
		var retiredAt int64
		if err := rows.Scan(&r.CertID, &r.CertName, &retiredAt, &r.CertPEM, &r.KeyPEM); err != nil {
			return nil, fmt.Errorf("scan archived material for %s: %w", certName, err)
		}
		if err := s.openRetiredMaterial(r); err != nil {
			return nil, err
		}
		r.RetiredAt = fromUnix(retiredAt)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) openRetiredMaterial(r *RetiredCert) error {
	if s.sealer == nil {
		return nil
	}
	if len(r.CertPEM) > 0 {
		plain, err := s.sealer.open(r.CertPEM, []byte("retired_certificates/cert_pem/"+r.CertID))
		if err != nil {
			return fmt.Errorf("decrypt retired certificate %s: %w", r.CertID, err)
		}
		r.CertPEM = plain
	}
	if len(r.KeyPEM) > 0 {
		plain, err := s.sealer.open(r.KeyPEM, []byte("retired_certificates/key_pem/"+r.CertID))
		if err != nil {
			return fmt.Errorf("decrypt retired certificate %s key: %w", r.CertID, err)
		}
		r.KeyPEM = plain
	}
	return nil
}

// DeleteRetiredCert removes an entry from the reclamation list (called after the
// cloud-side delete succeeds).
func (s *Store) DeleteRetiredCert(certID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM retired_certificates WHERE cert_id = ?`, certID)
	if err != nil {
		return fmt.Errorf("delete retired cert %s: %w", certID, err)
	}
	return nil
}
