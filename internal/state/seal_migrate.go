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
		// Collect first, then UPDATE after rows.Close(): SQLite does not promise that
		// a cursor visits a row exactly once when the same table is written while it
		// is open. A skipped row is a private key that stays plaintext and then
		// becomes unreadable under sealed open -- "not encrypted with this format".
		type pending struct {
			id     string
			sealed []byte
		}
		var todo []pending
		for rows.Next() {
			var id string
			var blob []byte
			if err := rows.Scan(&id, &blob); err != nil {
				rows.Close()
				return err
			}
			if bytes.HasPrefix(blob, sealedPrefixV2) {
				continue
			}
			// Plaintext or v1: seal (or re-seal) with the current KDF.
			//
			// A v1 blob must be OPENED first. Sealing its ciphertext would store
			// v2(v1(plain)) and the next open would peel only the v2 layer, handing
			// the caller a second AEAD blob instead of the private key -- a silent
			// brick that unit tests of seal/open alone cannot see.
			plain := blob
			if isSealedV1(blob) {
				opened, err := s.sealer.open(blob, []byte(spec.aad+id))
				if err != nil {
					rows.Close()
					return fmt.Errorf("open v1-sealed %s.%s %q for re-seal: %w", spec.table, spec.column, id, err)
				}
				plain = opened
			}
			sealed, err := s.sealer.seal(plain, []byte(spec.aad+id))
			if err != nil {
				rows.Close()
				return err
			}
			todo = append(todo, pending{id: id, sealed: sealed})
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		for _, item := range todo {
			if _, err := tx.Exec("UPDATE "+spec.table+" SET "+spec.column+" = ? WHERE "+spec.id+" = ?", item.sealed, item.id); err != nil {
				return err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit state key sealing migration: %w", err)
	}
	return nil
}
