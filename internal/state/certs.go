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
	"database/sql"
	"errors"
	"fmt"
	_ "modernc.org/sqlite"
	"time"
)

// Per-table CRUD, split out of state.go so one table lives in one file.
// Same package: every method is still on Store.

func (s *Store) ListCertNames() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT name FROM certificates ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list certificate names: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan certificate name: %w", err)
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// OrphanRow is one certificate as the orphan sweep sees it: the name, the expiry its report line
// prints, and when its teardown finished (zero: never).
type OrphanRow struct {
	Name            string
	NotAfter        time.Time
	OrphanCleanedAt time.Time
}

// ListOrphanRows returns every certificate with the fields the orphan sweep needs, in name order.
//
// ONE query for the whole pass, deliberately. The sweep already had to walk every name to find the
// orphans, so folding the mark -- and the expiry the per-orphan report line carries -- into that
// same read makes an already-cleaned orphan cost no statement at all. The alternative, a GetCert
// per name in the loop, is exactly the per-orphan cost the column exists to remove: measured with
// `-tags verifycount` at 2,999 orphans, one list query plus one GetCert and five CleanupOrphan
// statements each was 17,995 statements per pass, on every pass, forever.
//
// No certificate material is read here on purpose: cert_pem/key_pem are the largest columns in the
// table, and a sweep that runs every pass must not drag every fleet's private keys through the
// index for a report line.

func (s *Store) ListOrphanRows() ([]OrphanRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT name, not_after, orphan_cleaned_at FROM certificates ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list certificate names for the orphan sweep: %w", err)
	}
	defer rows.Close()

	var out []OrphanRow
	for rows.Next() {
		var (
			row            OrphanRow
			notAfter, mark int64
		)
		if err := rows.Scan(&row.Name, &notAfter, &mark); err != nil {
			return nil, fmt.Errorf("scan certificate row: %w", err)
		}
		row.NotAfter = fromUnix(notAfter)
		row.OrphanCleanedAt = fromUnix(mark)
		out = append(out, row)
	}
	return out, rows.Err()
}

// MarkOrphanCleaned records that the orphan teardown for this name finished, and reports whether
// the mark is set.
//
// The guard inside the UPDATE is what "finished" means here: the mark is refused while the name
// still has an order or an authorization row. Those rows are the residue cleanupOrphanTXT keeps on
// purpose when a TXT record could not be reclaimed -- or is still inside its propagation window, so
// the record may yet appear -- and the row carries the only clue for locating that record again. A
// mark written over that residue would stop the sweep from ever retrying it, stranding a stale
// _acme-challenge value that poisons every other certificate sharing the TXT name. An unmarked name
// is simply torn down again next pass, which is the pre-column behaviour and the correct one.
//
// One statement rather than a read followed by a write: the condition has to hold at the moment of
// the write anyway, so splitting it would add a check-then-act window and a round trip for nothing.
//
// The bool is "the mark is now set", not "this call changed it", so a caller can tell a completed
// teardown from one that will be retried.
func (s *Store) MarkOrphanCleaned(name string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`
		UPDATE certificates SET orphan_cleaned_at = ?
		WHERE name = ?
		  AND NOT EXISTS (SELECT 1 FROM orders         WHERE cert_name = certificates.name)
		  AND NOT EXISTS (SELECT 1 FROM authorizations WHERE cert_name = certificates.name)`,
		time.Now().Unix(), name)
	if err != nil {
		return false, fmt.Errorf("mark orphan cleaned %s: %w", name, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("mark orphan cleaned %s: %w", name, err)
	}
	return n > 0, nil
}

// ClearOrphanCleaned drops the mark, so a name that leaves the desired state again is torn down
// again.
//
// Called when the name is back in the desired state (see reconcile.publishOrphans and
// reconcile.publish). The mark says "left the desired state and was torn down"; leaving it set past
// the return would let it outlive the condition it describes -- the next departure would be
// skipped, and the certificate would keep whatever its renewed pass left behind: an order, its TXT
// records, its per-certificate and per-host metric series.
//
// `AND orphan_cleaned_at != 0` keeps a call for an unmarked name from writing a row (and a WAL
// frame) to say nothing.
func (s *Store) ClearOrphanCleaned(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.db.Exec(
		`UPDATE certificates SET orphan_cleaned_at = 0 WHERE name = ? AND orphan_cleaned_at != 0`,
		name); err != nil {
		return fmt.Errorf("clear orphan cleaned %s: %w", name, err)
	}
	return nil
}

// UpdateCert applies fn to one certificate's state and writes the result back, all while
// holding the store lock.
//
// This is the form callers should prefer over GetCert followed by PutCert: the read and
// the write have to be one operation or a concurrent writer's change is silently lost.
// fn must not call back into the Store.
//
// A missing row is an error rather than an upsert: a name typo should surface, not create
// a phantom certificate that then appears in the orphan report.
func (s *Store) UpdateCert(name string, fn func(*CertState) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, err := s.getCertLocked(name)
	if err != nil {
		return err
	}
	if st == nil {
		return fmt.Errorf("update cert %s: no such certificate in the state store", name)
	}
	if err := fn(st); err != nil {
		return err
	}
	return s.putCertLocked(st)
}

// GetCert reads certificate state; returns (nil, nil) when it does not exist.
func (s *Store) GetCert(name string) (*CertState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getCertLocked(name)
}

func (s *Store) getCertLocked(name string) (*CertState, error) {
	row := s.db.QueryRow(`
		SELECT name, not_after, cert_url, cert_pem, key_pem, issued_at,
		       ari_cert_id, ari_window_start, ari_window_end, ari_checked_at, ari_retry_after_ns,
		       consecutive_failures, next_attempt_at, last_error, deployed_cert_id,
		       deploy_confirmed, orphan_cleaned_at, updated_at
		FROM certificates WHERE name = ?`, name)

	c := &CertState{}
	var notAfter, issuedAt, ariStart, ariEnd, ariChecked, nextAttempt, updatedAt int64
	var retryAfterNS int64
	var orphanCleanedAt int64
	var deployConfirmed bool

	err := row.Scan(
		&c.Name, &notAfter, &c.CertURL, &c.CertPEM, &c.KeyPEM, &issuedAt,
		&c.ARICertID, &ariStart, &ariEnd, &ariChecked, &retryAfterNS,
		&c.ConsecutiveFailures, &nextAttempt, &c.LastError, &c.DeployedCertID,
		&deployConfirmed, &orphanCleanedAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get cert %s: %w", name, err)
	}

	c.NotAfter = fromUnix(notAfter)
	c.IssuedAt = fromUnix(issuedAt)
	c.ARIWindowStart = fromUnix(ariStart)
	c.ARIWindowEnd = fromUnix(ariEnd)
	c.ARICheckedAt = fromUnix(ariChecked)
	c.ARIRetryAfter = time.Duration(retryAfterNS)
	c.NextAttemptAt = fromUnix(nextAttempt)
	c.DeployConfirmed = deployConfirmed
	c.OrphanCleanedAt = fromUnix(orphanCleanedAt)
	c.UpdatedAt = fromUnix(updatedAt)
	if s.sealer != nil {
		if len(c.CertPEM) > 0 {
			plain, err := s.sealer.open(c.CertPEM, []byte("certificates/cert_pem/"+c.Name))
			if err != nil {
				return nil, fmt.Errorf("get cert %s: %w", name, err)
			}
			c.CertPEM = plain
		}
		if len(c.KeyPEM) > 0 {
			plain, err := s.sealer.open(c.KeyPEM, []byte("certificates/key_pem/"+c.Name))
			if err != nil {
				return nil, fmt.Errorf("get cert %s: %w", name, err)
			}
			c.KeyPEM = plain
		}
	}
	return c, nil
}

// PutCert writes certificate state.
func (s *Store) PutCert(c *CertState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putCertLocked(c)
}

func (s *Store) putCertLocked(c *CertState) error {
	if s.sealer == nil {
		return putCertExec(s.db, c)
	}
	copy := *c
	if len(copy.CertPEM) > 0 {
		sealed, err := s.sealer.seal(copy.CertPEM, []byte("certificates/cert_pem/"+copy.Name))
		if err != nil {
			return fmt.Errorf("seal certificate material for %s: %w", copy.Name, err)
		}
		copy.CertPEM = sealed
	}
	if len(copy.KeyPEM) > 0 {
		sealed, err := s.sealer.seal(copy.KeyPEM, []byte("certificates/key_pem/"+copy.Name))
		if err != nil {
			return fmt.Errorf("seal certificate key for %s: %w", copy.Name, err)
		}
		copy.KeyPEM = sealed
	}
	return putCertExec(s.db, &copy)
}

func putCertExec(e execer, c *CertState) error {
	_, err := e.Exec(`
		INSERT INTO certificates (
			name, not_after, cert_url, cert_pem, key_pem, issued_at,
			ari_cert_id, ari_window_start, ari_window_end, ari_checked_at, ari_retry_after_ns,
			consecutive_failures, next_attempt_at, last_error, deployed_cert_id,
			deploy_confirmed, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET
			not_after            = excluded.not_after,
			cert_url             = excluded.cert_url,
			cert_pem             = excluded.cert_pem,
			key_pem              = excluded.key_pem,
			issued_at            = excluded.issued_at,
			ari_cert_id          = excluded.ari_cert_id,
			ari_window_start     = excluded.ari_window_start,
			ari_window_end       = excluded.ari_window_end,
			ari_checked_at       = excluded.ari_checked_at,
			ari_retry_after_ns   = excluded.ari_retry_after_ns,
			consecutive_failures = excluded.consecutive_failures,
			next_attempt_at      = excluded.next_attempt_at,
			last_error           = excluded.last_error,
			deployed_cert_id     = excluded.deployed_cert_id,
			deploy_confirmed     = excluded.deploy_confirmed,
			updated_at           = excluded.updated_at`,
		c.Name, toUnix(c.NotAfter), c.CertURL, c.CertPEM, c.KeyPEM, toUnix(c.IssuedAt),
		c.ARICertID, toUnix(c.ARIWindowStart), toUnix(c.ARIWindowEnd), toUnix(c.ARICheckedAt),
		int64(c.ARIRetryAfter),
		// Truncated at the one place every caller funnels through, not in each
		// producer. last_error carries upstream text: lego embeds the whole non-JSON
		// ACME error body in its errors, and the CVM metadata path echoes part of a
		// response body. Unbounded, that is both a growth vector and remote-controlled
		// text that /hook/status serves and notifyURL posts off-host. The identifier
		// ledger already bounds its equivalent at 512 (fallback.go); this is the same
		// rule applied where it cannot be forgotten.
		c.ConsecutiveFailures, toUnix(c.NextAttemptAt), truncate(c.LastError, maxLastErrorBytes),
		c.DeployedCertID, c.DeployConfirmed, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("put cert %s: %w", c.Name, err)
	}
	return nil
}

// RecordFailure updates only the failure-bookkeeping columns --
// consecutive_failures, last_error, next_attempt_at -- and never touches the
// certificate material (cert_pem, key_pem, not_after, deployed_cert_id,
// ari_cert_id, ...).
//
// It exists because the failure path (acme's recordFailure) may be holding a
// CertState synthesised from a failed read: funnelling that through PutCert's
// whole-row overwrite upsert would blank the private key and PEM of the
// certificate currently in service. Failure bookkeeping needs only these three
// columns, so the write surface is narrowed to them. When no row exists yet it
// inserts one carrying just these fields; every other column falls to its
// schema default (each NOT NULL column of certificates has a DEFAULT, and
// cert_pem/key_pem are nullable), which matches what putCertExec's INSERT
// branch produces for a fresh row.
//
// The two counters are merged with MAX, not overwritten.
//
// The only caller is the path taken when the row could NOT be read, so the count it can
// compute ("at least one failure: this one") is a lower bound, never the whole truth.
// Overwriting with it destroyed evidence already on disk: a certificate that had failed
// eight times straight and then hit one unreadable row went back to 1, which reset the
// exponential backoff to its base window AND dropped it below the threshold the failure
// fallback needs to trigger (ConsecutiveFailures >= 5), so a certificate that most needed
// degrading was the one that could never degrade. MAX keeps the higher of the two: the
// stored count is the same fact observed more completely.
//
// A successful pass still clears both -- it goes through PutCert, which is a whole-row
// upsert and writes consecutive_failures from the CertState -- so MAX cannot strand a
// stale backoff after recovery.
func (s *Store) RecordFailure(name, lastErr string, consecutiveFailures int, nextAttemptAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`
		INSERT INTO certificates (name, consecutive_failures, next_attempt_at, last_error, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET
			consecutive_failures = MAX(consecutive_failures, excluded.consecutive_failures),
			next_attempt_at      = MAX(next_attempt_at, excluded.next_attempt_at),
			last_error           = excluded.last_error,
			updated_at           = excluded.updated_at`,
		// last_error is bounded here for the same reason putCertExec bounds it (see
		// maxLastErrorBytes): upstream error text is unbounded remote-controlled data,
		// and the point of persistence is the one place the rule cannot be forgotten.
		name, consecutiveFailures, toUnix(nextAttemptAt),
		truncate(lastErr, maxLastErrorBytes), time.Now().Unix())
	if err != nil {
		return fmt.Errorf("record failure for %s: %w", name, err)
	}
	return nil
}

// ---------- Order ----------

// GetOrder reads the in-flight order; returns (nil, nil) when it does not exist.
