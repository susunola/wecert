package state

import "database/sql"

// openSQLForTest opens a bare connection to a state database file, for tests that need to build or
// damage one without going through Store's locking and migration.
func openSQLForTest(path string) (*sql.DB, error) { return sql.Open("sqlite", path) }
