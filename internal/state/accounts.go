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
	_ "modernc.org/sqlite" // pure Go driver: no CGO, which keeps static builds easy
)

// Per-table CRUD, split out of state.go so one table lives in one file.
// Same package: every method is still on Store.

func (s *Store) GetAccount(directory string) (*Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row := s.db.QueryRow(
		`SELECT directory, kid, private_key_pem FROM accounts WHERE directory = ?`, directory)
	a := &Account{}
	err := row.Scan(&a.Directory, &a.KID, &a.PrivateKeyPEM)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get account: %w", err)
	}
	return a, nil
}

// PutAccountWithoutKey writes an account row whose private key is empty.
//
// Only for tests and for reproducing a legacy row. It cannot be written as NULL --
// private_key_pem is declared NOT NULL, which is the point of checking the length rather than
// nil-ness in the loader: a row from a database written before that constraint existed reads
// back as nil, and an empty blob reads back the same way. Both mean "no usable key".
