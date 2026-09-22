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
	_ "modernc.org/sqlite" // pure Go driver: no CGO, which keeps static builds easy
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
