package state

// unsafeFilesystem is a seam around the platform-specific filesystem check.
//
// SQLite's locking and this package's flock gate both rely on local filesystem
// semantics.  On a network mount two hosts can each believe they own the lock,
// then write one state database independently -- exactly the failure the lock
// exists to prevent.  Keep the policy here, close to Open, rather than relying
// on a deployment document being remembered at the moment a new statePath is
// chosen.
var unsafeFilesystem = unsafeFilesystemForPath
