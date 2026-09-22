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
	o.ExpiresAt = fromUnix(expiresAt)
	return o, nil
}

// PutOrder writes the in-flight order.
