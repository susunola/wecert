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

func (s *Store) GetOrder(certName string) (*Order, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row := s.db.QueryRow(`
		SELECT cert_name, order_url, finalize_url, cert_url, expires_at, status, key_pem, identifiers, deployment_cert_id
		FROM orders WHERE cert_name = ?`, certName)

	o := &Order{}
	var expiresAt int64
	err := row.Scan(&o.CertName, &o.OrderURL, &o.FinalizeURL, &o.CertURL, &expiresAt,
		&o.Status, &o.KeyPEM, &o.Identifiers, &o.DeploymentCertID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get order for %s: %w", certName, err)
	}
	if s.sealer != nil && len(o.KeyPEM) > 0 {
		plain, err := s.sealer.open(o.KeyPEM, []byte("orders/key_pem/"+o.CertName))
		if err != nil {
			return nil, fmt.Errorf("get order for %s: %w", certName, err)
		}
		o.KeyPEM = plain
	}
	o.ExpiresAt = fromUnix(expiresAt)
	return o, nil
}

// PutOrder writes the in-flight order.

func (s *Store) PutOrder(o *Order) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := o.KeyPEM
	if s.sealer != nil && len(key) > 0 {
		var err error
		key, err = s.sealer.seal(key, []byte("orders/key_pem/"+o.CertName))
		if err != nil {
			return fmt.Errorf("seal order key for %s: %w", o.CertName, err)
		}
	}
	_, err := s.db.Exec(`
		INSERT INTO orders (
			cert_name, order_url, finalize_url, cert_url, expires_at, status, key_pem, identifiers, deployment_cert_id, updated_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(cert_name) DO UPDATE SET
			order_url    = excluded.order_url,
			finalize_url = excluded.finalize_url,
			cert_url     = excluded.cert_url,
			expires_at   = excluded.expires_at,
			status       = excluded.status,
			key_pem      = excluded.key_pem,
			identifiers  = excluded.identifiers,
			deployment_cert_id = excluded.deployment_cert_id,
			updated_at   = excluded.updated_at`,
		o.CertName, o.OrderURL, o.FinalizeURL, o.CertURL, toUnix(o.ExpiresAt), o.Status,
		key, o.Identifiers, o.DeploymentCertID, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("put order for %s: %w", o.CertName, err)
	}
	return nil
}

// DeleteOrder discards the current order (it expired or was abandoned).
func (s *Store) DeleteOrder(certName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return deleteOrderExec(s.db, certName)
}

func deleteOrderExec(e execer, certName string) error {
	if _, err := e.Exec(`DELETE FROM orders WHERE cert_name = ?`, certName); err != nil {
		return fmt.Errorf("delete order for %s: %w", certName, err)
	}
	return nil
}

// ---------- Authorization ----------

// ListAuthorizations lists every authorization under a certificate's order.
