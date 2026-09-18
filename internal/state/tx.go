package state

import (
	"context"
	"database/sql"
	"fmt"
)

// Transactions.
//
// Why this exists at all, given that every method here already takes s.mu: the mutex serialises
// calls *within this process*, and the pool is capped at one connection, but neither makes a
// SEQUENCE of statements atomic. The place that matters is the end of a renewal -- promote the new
// certificate, retire the old one, discard the order -- where a crash or a store error between two
// statements used to leave a state no later pass could repair:
//
//   - promote landed, retire did not: the certificate that was serving is in no table at all, so
//     ReapRetired never sees it, nothing ever deletes it from the cloud, and it holds a slot in
//     the account's uploaded-certificate quota until somebody notices. Quota exhaustion is what
//     stops renewal.
//   - promote did not land, retire did: the certificate still bound to the listener is marked for
//     deletion. Same mistake, dangerous direction.
//
// With one transaction either all of it lands or none of it does, and "none" is a state the next
// pass already knows how to handle: it runs the epilogue again.
//
// The statements run over database/sql's own Tx. What makes it IMMEDIATE is `_txlock=immediate` in
// the DSN (state.go): in WAL, a deferred transaction that reads before it writes can fail at COMMIT
// with SQLITE_BUSY after doing all its work, which reads as a commit bug rather than a lock
// conflict. Taking the write lock at BEGIN turns that into a wait, which is what busy_timeout is
// for.

// Tx is one transaction over the state database.
//
// Its methods are the writes the renewal epilogue needs. They deliberately do not lock: WithTx
// holds the store's mutex for the whole transaction, and taking it again here would deadlock.
type Tx struct {
	tx *sql.Tx
}

// WithTx runs fn inside a single transaction.
//
// fn's error rolls the transaction back and is returned unchanged. A panic from fn also rolls the
// transaction back, and then PROPAGATES -- WithTx does not recover it, so it reaches the caller as
// a panic, not as an error. That rollback-on-the-way-out matters more than it looks, because a
// panic in the middle of the epilogue is exactly the partial state this exists to prevent.
//
// Reads made through the store (not through Tx) inside fn DO NOT WORK AT ALL: every store method
// takes s.mu, WithTx holds it for the whole transaction, and the mutex is not reentrant -- so such a
// read blocks forever on a lock only this goroutine could release. The context does not help (the
// store's methods do not take one), and the held mutex then freezes every later store call, Close
// included. An earlier version of this comment said the read "sees the pre-transaction state",
// which was both wrong and reassuring: the first maintainer to believe it gets a deadlock instead of
// a stale value.
//
// Read everything you need through Tx (or before entering). Both production callbacks obey this;
// it is enforced by nothing but this paragraph, which is why it says what actually happens.
//
// Holding s.mu for the whole transaction also makes the periodic snapshot consistent for free:
// Snapshot takes the same mutex, so a backup always sees the state either entirely before or
// entirely after the epilogue, never half of it.
func (s *Store) WithTx(ctx context.Context, fn func(*Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	// Rollback after a successful Commit returns sql.ErrTxDone, which is expected and ignored.
	defer func() { _ = tx.Rollback() }()

	if err := fn(&Tx{tx: tx}); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// PutCert writes the certificate row inside the transaction.
func (t *Tx) PutCert(c *CertState) error { return putCertExec(t.tx, c) }

// AddRetiredCert records a certificate for reclamation inside the transaction.
func (t *Tx) AddRetiredCert(certID, certName string, certPEM, keyPEM []byte) error {
	return addRetiredCertExec(t.tx, certID, certName, certPEM, keyPEM)
}

// DeleteOrder removes the in-flight order row inside the transaction.
func (t *Tx) DeleteOrder(certName string) error { return deleteOrderExec(t.tx, certName) }

// ClearFallback removes the certificate's fallback record inside the transaction.
func (t *Tx) ClearFallback(certName string) error { return clearFallbackExec(t.tx, certName) }

// ClearIdentifierFailures clears the per-identifier failure ledger inside the transaction.
func (t *Tx) ClearIdentifierFailures(certName string) error {
	return clearIdentifierFailuresExec(t.tx, certName)
}
