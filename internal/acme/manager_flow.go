package acme

import ()

// authzFetchConcurrency caps how many authorization lookups are in flight at once.
//
// On certificates with many SANs this step must be concurrent: pulling 100 authorizations
// serially is 100 round trips, and a 3-minute wait budget does not survive many rounds. The
// cap of 8 is there to avoid hitting the CA with a burst.
//
// The concurrency is safe because of how lego is built: once constructed, api.Core carries
// only mutable state like the nonce manager, and that one has a mutex; the JWS and Doer are
// read-only.
const authzFetchConcurrency = 8

// advance pushes the order state machine forward.
type txtReclaim int

const (
	// txtReclaimDone: the record was reclaimed, or proved absent -- the row can be deleted.
	txtReclaimDone txtReclaim = iota
	// txtReclaimKeptPropagating: denied, but inside the propagation window; keep the row and retry.
	txtReclaimKeptPropagating
	// txtReclaimFailed: the probe or the cleanup failed; keep the row and retry next round.
	txtReclaimFailed
)

// reclaimUnpresentedTXT probes DNS for the record of an authorization whose row says
// Presented=false but which carries a challenge token -- the fingerprint of a pass that
// died between the DNS write and the state persist. It returns txtReclaimFailed when the
// record's fate is unknown (the probe failed, or the record is up but would not delete), and
// then the caller must keep the row: its token is the only clue for locating the record again.
