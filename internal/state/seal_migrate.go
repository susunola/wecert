package state

import (
	"bytes"
	"fmt"
)

// migrateSealedMaterial upgrades every existing private-material blob as one
// transaction. It is idempotent: a crash rolls the transaction back, and a
// successful restart recognizes the version prefix rather than encrypting twice.
func (s *Store) migrateSealedMaterial() error {
	if s.sealer == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	type row struct{ table, id, column, aad string }
	for _, spec := range []struct{ table, id, column, aad string }{
		{"accounts", "directory", "private_key_pem", "accounts/private_key_pem/"},
		{"orders", "cert_name", "key_pem", "orders/key_pem/"},
		{"certificates", "name", "cert_pem", "certificates/cert_pem/"},
		{"certificates", "name", "key_pem", "certificates/key_pem/"},
		{"retired_certificates", "cert_id", "cert_pem", "retired_certificates/cert_pem/"},
		{"retired_certificates", "cert_id", "key_pem", "retired_certificates/key_pem/"},
	} {
		rows, err := tx.Query("SELECT " + spec.id + ", " + spec.column + " FROM " + spec.table + " WHERE " + spec.column + " IS NOT NULL AND length(" + spec.column + ") > 0")
		if err != nil {
			return fmt.Errorf("read %s.%s for sealing: %w", spec.table, spec.column, err)
		}
		for rows.Next() {
			var id string
			var blob []byte
			if err := rows.Scan(&id, &blob); err != nil {
				rows.Close()
				return err
			}
			if bytes.HasPrefix(blob, sealedPrefix) {
				continue
			}
			sealed, err := s.sealer.seal(blob, []byte(spec.aad+id))
			if err != nil {
				rows.Close()
				return err
			}
			if _, err := tx.Exec("UPDATE "+spec.table+" SET "+spec.column+" = ? WHERE "+spec.id+" = ?", sealed, id); err != nil {
				rows.Close()
				return err
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit state key sealing migration: %w", err)
	}
	return nil
}
