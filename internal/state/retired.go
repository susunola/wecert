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
	return addRetiredCertExec(s.db, certID, certName, certPEM, keyPEM)
}
