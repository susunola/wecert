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
	if s.sealer != nil && len(a.PrivateKeyPEM) > 0 {
		plain, err := s.sealer.open(a.PrivateKeyPEM, []byte("accounts/private_key_pem/"+a.Directory))
		if err != nil {
			return nil, fmt.Errorf("get account: %w", err)
		}
		a.PrivateKeyPEM = plain
	}
	return a, nil
}

// PutAccountWithoutKey writes an account row whose private key is empty.
//
// Only for tests and for reproducing a legacy row. It cannot be written as NULL --
// private_key_pem is declared NOT NULL, which is the point of checking the length rather than
// nil-ness in the loader: a row from a database written before that constraint existed reads
// back as nil, and an empty blob reads back the same way. Both mean "no usable key".

func (s *Store) PutAccountWithoutKey(directory, kid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(
		`INSERT INTO accounts (directory, kid, private_key_pem, updated_at) VALUES (?, ?, x'', ?)`,
		directory, kid, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("put account %s without a key: %w", directory, err)
	}
	return nil
}

// PutAccount writes the account.
func (s *Store) PutAccount(a *Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := a.PrivateKeyPEM
	if s.sealer != nil && len(key) > 0 {
		var err error
		key, err = s.sealer.seal(key, []byte("accounts/private_key_pem/"+a.Directory))
		if err != nil {
			return fmt.Errorf("seal account key: %w", err)
		}
	}
	_, err := s.db.Exec(`
		INSERT INTO accounts (directory, kid, private_key_pem, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(directory) DO UPDATE SET
			kid = excluded.kid,
			private_key_pem = excluded.private_key_pem,
			updated_at = excluded.updated_at`,
		a.Directory, a.KID, key, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("put account: %w", err)
	}
	return nil
}

// ---------- CertState ----------

// ListCertNames returns every certificate name in the state database, sorted.
//
// Its purpose is the "orphan check": a certificate present in the state database but
// gone from the desired state will never be renewed again and will quietly expire.
// Making this set visible is the only backstop for that failure path.
