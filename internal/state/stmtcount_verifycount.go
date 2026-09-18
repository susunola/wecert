//go:build verifycount

// This file is a measuring instrument, not a product feature. It compiles only with
// `-tags verifycount`, so the shipped binary never carries it.

package state

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"sync/atomic"

	sqlite "modernc.org/sqlite"
)

// CountedStatements counts every statement the store has sent to SQLite, process-wide.
//
// It exists so a test can measure what a pass costs the database -- the round-11 scale work counted
// them with a harness in a scratch copy; this makes the number reproducible from the real code.
var CountedStatements atomic.Int64

// OpenCounted is Open with the statement counter in place.
//
// It swaps the package's openStateDB seam for a counting driver.Connector rather than registering a
// fake driver NAME, because the counter has to wrap the very connection the store uses and
// database/sql caches connections by driver: the connector hands out the wrapper for every
// connection the pool opens, and nothing else about the store changes.
func OpenCounted(path string) (*Store, error) {
	saved := openStateDB
	openStateDB = func(dsn string) (*sql.DB, error) {
		return sql.OpenDB(countingConnector{dsn: dsn}), nil
	}
	defer func() { openStateDB = saved }()
	return Open(path)
}

func init() {
	// Every connection this build opens goes through the counting driver, whichever opener asked
	// for it, so a test cannot accidentally measure an uncounted pool.
	openStateDB = func(dsn string) (*sql.DB, error) {
		return sql.OpenDB(countingConnector{dsn: dsn}), nil
	}
}

type countingConnector struct{ dsn string }

func (c countingConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := (&sqlite.Driver{}).Open(c.dsn)
	if err != nil {
		return nil, err
	}
	return &countingConn{inner: conn}, nil
}

func (c countingConnector) Driver() driver.Driver { return &countingDriver{} }

type countingDriver struct{}

func (countingDriver) Open(dsn string) (driver.Conn, error) {
	conn, err := (&sqlite.Driver{}).Open(dsn)
	if err != nil {
		return nil, err
	}
	return &countingConn{inner: conn}, nil
}

// countingConn preserves every optional database/sql interface the modernc connection implements,
// so the store keeps its single-connection, immediate-transaction behaviour.
type countingConn struct{ inner driver.Conn }

func (c *countingConn) Prepare(query string) (driver.Stmt, error) {
	CountedStatements.Add(1)
	s, err := c.inner.Prepare(query)
	if err != nil {
		return nil, err
	}
	return &countingStmt{inner: s}, nil
}

func (c *countingConn) Close() error { return c.inner.Close() }

func (c *countingConn) Begin() (driver.Tx, error) {
	CountedStatements.Add(1)
	return c.inner.Begin()
}

func (c *countingConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	CountedStatements.Add(1)
	return c.inner.(driver.ExecerContext).ExecContext(ctx, q, args)
}

func (c *countingConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	CountedStatements.Add(1)
	return c.inner.(driver.QueryerContext).QueryContext(ctx, q, args)
}

func (c *countingConn) PrepareContext(ctx context.Context, q string) (driver.Stmt, error) {
	CountedStatements.Add(1)
	s, err := c.inner.(driver.ConnPrepareContext).PrepareContext(ctx, q)
	if err != nil {
		return nil, err
	}
	return &countingStmt{inner: s}, nil
}

func (c *countingConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	CountedStatements.Add(1)
	return c.inner.(driver.ConnBeginTx).BeginTx(ctx, opts)
}

func (c *countingConn) Ping(ctx context.Context) error { return c.inner.(driver.Pinger).Ping(ctx) }

func (c *countingConn) ResetSession(ctx context.Context) error {
	if r, ok := c.inner.(driver.SessionResetter); ok {
		return r.ResetSession(ctx)
	}
	return nil
}

func (c *countingConn) IsValid() bool {
	if v, ok := c.inner.(driver.Validator); ok {
		return v.IsValid()
	}
	return true
}

type countingStmt struct{ inner driver.Stmt }

func (s *countingStmt) Close() error  { return s.inner.Close() }
func (s *countingStmt) NumInput() int { return s.inner.NumInput() }

func (s *countingStmt) Exec(args []driver.Value) (driver.Result, error) {
	return s.inner.Exec(args)
}

func (s *countingStmt) Query(args []driver.Value) (driver.Rows, error) {
	return s.inner.Query(args)
}

func (s *countingStmt) ExecContext(ctx context.Context, args []driver.NamedValue) (driver.Result, error) {
	CountedStatements.Add(1)
	return s.inner.(driver.StmtExecContext).ExecContext(ctx, args)
}

func (s *countingStmt) QueryContext(ctx context.Context, args []driver.NamedValue) (driver.Rows, error) {
	CountedStatements.Add(1)
	return s.inner.(driver.StmtQueryContext).QueryContext(ctx, args)
}
