package state

// schemaDDL is the CREATE TABLE set migrate applies. Kept out of migrate so the
// function stays readable as "run DDL, then patch columns".
const schemaDDL = `
CREATE TABLE IF NOT EXISTS accounts (
    directory       TEXT PRIMARY KEY,
    kid             TEXT NOT NULL,
    private_key_pem BLOB NOT NULL,
    updated_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS certificates (
    name                 TEXT PRIMARY KEY,
    not_after            INTEGER NOT NULL DEFAULT 0,
    cert_url             TEXT    NOT NULL DEFAULT '',
    cert_pem             BLOB,
    key_pem              BLOB,
    issued_at            INTEGER NOT NULL DEFAULT 0,
    ari_cert_id          TEXT    NOT NULL DEFAULT '',
    ari_window_start     INTEGER NOT NULL DEFAULT 0,
    ari_window_end       INTEGER NOT NULL DEFAULT 0,
    ari_checked_at       INTEGER NOT NULL DEFAULT 0,
    ari_retry_after_ns   INTEGER NOT NULL DEFAULT 0,
    consecutive_failures   INTEGER NOT NULL DEFAULT 0,
    next_attempt_at        INTEGER NOT NULL DEFAULT 0,
    last_error             TEXT    NOT NULL DEFAULT '',
    deployed_cert_id       TEXT    NOT NULL DEFAULT '',
    -- Upload success != bound to the listener. Only set once the one-click update
    -- has actually swapped it over; otherwise the first upload is treated as
    -- "deployed" and metrics go green before a human has bound anything.
    deploy_confirmed       INTEGER NOT NULL DEFAULT 0,
    -- When this name's orphan teardown finished (unix seconds). 0 means never.
    --
    -- The row of a certificate that left the desired state is kept on purpose -- that is what
    -- preserves its history if the name comes back -- so the orphan sweep sees it again on every
    -- pass. This column is the durable "already torn down" mark that lets the sweep report it
    -- without paying for its teardown a second time; an in-memory set would be a second map
    -- growing with churn, and would forget everything on restart, which is exactly when a fleet
    -- edit is most likely to happen.
    --
    -- Written only by MarkOrphanCleaned and cleared only by ClearOrphanCleaned: putCertExec
    -- deliberately leaves it out of its column list (see CertState.OrphanCleanedAt).
    orphan_cleaned_at      INTEGER NOT NULL DEFAULT 0,
    updated_at             INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS orders (
    cert_name    TEXT PRIMARY KEY,
    order_url    TEXT NOT NULL,
    finalize_url TEXT NOT NULL DEFAULT '',
    cert_url     TEXT NOT NULL DEFAULT '',
    expires_at   INTEGER NOT NULL DEFAULT 0,
    status       TEXT NOT NULL DEFAULT '',
    key_pem      BLOB,
    -- The identifier set submitted at newOrder time (canonical form, see config.DomainKey).
    identifiers  TEXT NOT NULL DEFAULT '',
    deployment_cert_id TEXT NOT NULL DEFAULT '',
    updated_at   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS authorizations (
    cert_name       TEXT NOT NULL,
    authz_url       TEXT NOT NULL,
    identifier      TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT '',
    challenge_url   TEXT NOT NULL DEFAULT '',
    challenge_token TEXT NOT NULL DEFAULT '',
    txt_name        TEXT NOT NULL DEFAULT '',
    txt_value       TEXT NOT NULL DEFAULT '',
    presented       INTEGER NOT NULL DEFAULT 0,
    challenge_sent  INTEGER NOT NULL DEFAULT 0,
    -- When the challenge currently in this row was chosen (see the acme package). Crash recovery
    -- needs it: an authoritative "no such record" is only trustworthy once the write would have had
    -- time to propagate, and DNSPod's authoritative servers lag the API write by up to a minute.
    challenge_prepared_at INTEGER NOT NULL DEFAULT 0,
    -- DNS cleanup guardian: how often a reclaim of this row has been attempted and failed,
    -- since when it has been stuck (0 = not stuck), and why the last attempt failed. The
    -- row is the retry queue for "TXT may still be in DNS but authoritative NS is
    -- unreachable / the provider cannot delete it".
    reclaim_attempts     INTEGER NOT NULL DEFAULT 0,
    reclaim_last_error   TEXT    NOT NULL DEFAULT '',
    reclaim_stuck_since  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (cert_name, authz_url)
);

-- Cloud certificates that are retired but not yet deleted. Kept for a while to allow
-- rollback, then they must be reclaimed: Tencent Cloud accounts have a quota on the
-- number of uploaded certificates.
--
-- cert_pem / key_pem are the archived material for the retired certificate, so it can be
-- re-uploaded and re-bound during the retention window.
--
-- This table used to hold only the CertId, and the retired certificate's key was
-- overwritten in the certificates row at the moment of renewal -- so "rollback" meant
-- "whatever the cloud still has", and after the retention period deleted it, wecert had
-- nothing to restore from. The comment here and in the deployer claimed rollback was the
-- point; now the material is actually retained, and pruned with the row.
CREATE TABLE IF NOT EXISTS retired_certificates (
    cert_id    TEXT PRIMARY KEY,
    cert_name  TEXT NOT NULL,
    retired_at INTEGER NOT NULL,
    cert_pem   BLOB,
    key_pem    BLOB
);

-- Per-identifier authorization failure ledger.
--
-- The certificate-level consecutive_failures only tells you "this certificate cannot
-- be issued", whereas pre-expiry fallback has to answer "**which name** cannot be
-- issued" -- without that, the only option is dropping names at random, which
-- sacrifices names that were fine to begin with.
--
-- last_failed_at also provides self-healing: once a failure record ages out, that
-- identifier stops being dropped and the next round naturally retries the full set.
-- No extra retry state is needed.
CREATE TABLE IF NOT EXISTS identifier_failures (
    cert_name      TEXT NOT NULL,
    identifier     TEXT NOT NULL,
    failures       INTEGER NOT NULL DEFAULT 0,
    last_error     TEXT NOT NULL DEFAULT '',
    last_failed_at INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (cert_name, identifier)
);

-- The currently active fallback state: this certificate is serving a certificate that
-- is missing some names.
--
-- A separate table rather than extra columns on certificates: this is not a property
-- of the certificate but an "incident in progress", and its lifecycle is completely
-- different -- it should be cleared once the full set issues successfully, while
-- certificate renewal must not touch it.
CREATE TABLE IF NOT EXISTS cert_fallback (
    cert_name TEXT PRIMARY KEY,
    dropped   TEXT NOT NULL DEFAULT '',
    since     INTEGER NOT NULL DEFAULT 0,
    reason    TEXT NOT NULL DEFAULT ''
);

-- Rate-limit bucket snapshots.
--
-- Let's Encrypt publishes its limits and their token-bucket refill rates but offers no way
-- to query the remaining allowance, so the only way to answer "how much is left" is to
-- account for what this program spent. A bucket needs no event log: the model is the memory,
-- so one row per (limit, scope) holding the last known level and when it was observed can be
-- rolled forward to any later instant.
--
-- scope_id is empty for account-wide limits and holds the registered domain / identifier
-- otherwise. reset_at is an AUTHORITATIVE instant the CA reported ("retry after ..."), which
-- beats the local estimate because the estimate cannot see other accounts spending the same
-- global bucket.
-- Revocation requests that have not succeeded yet.
--
-- A row here means "an operator decided this certificate must be revoked, and the CA has not
-- accepted it yet". Persisted rather than attempted once because revocation can fail for
-- entirely transient reasons (network, CA 5xx) and the decision must not be lost with the
-- process: a leaked private key does not stop being leaked because the request timed out.
--
-- The alternative -- only revoking synchronously from a CLI -- leaves a failed attempt as a
-- message on someone's terminal, with no record that the operator ever asked.
--
-- reason is the RFC 5280 CRLReason code, so the reason the operator chose survives into every
-- retry rather than being lost after the first attempt.
CREATE TABLE IF NOT EXISTS revoke_requests (
    cert_name   TEXT PRIMARY KEY,
    reason      INTEGER NOT NULL DEFAULT 0,
    -- The certificate the operator asked to revoke, as an identity derived from its material
    -- (see acme.certIdentity). Without it the retry revoked "whatever is stored under this name
    -- now" -- and a renewal between the request and the retry replaces exactly that, so the
    -- request could revoke the NEW certificate while the compromised one stayed valid, then
    -- clear itself as a success. Empty means unknown: a request recorded by an older build.
    cert_identity TEXT NOT NULL DEFAULT '',
    requested_at INTEGER NOT NULL DEFAULT 0,
    attempts    INTEGER NOT NULL DEFAULT 0,
    last_error  TEXT NOT NULL DEFAULT '',
    last_attempt_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS rate_buckets (
    limit_name TEXT NOT NULL,
    scope_id   TEXT NOT NULL DEFAULT '',
    tokens     REAL NOT NULL DEFAULT 0,
    observed_at INTEGER NOT NULL DEFAULT 0,
    reset_at   INTEGER NOT NULL DEFAULT 0,
    reset_reason TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (limit_name, scope_id)
);

-- A monotonic generation is deliberately outside certificate state.  The sidecar
-- mirror lets a later start notice a hand-copied older database before it places
-- another order against a rate-limit ledger that has moved backwards.
CREATE TABLE IF NOT EXISTS state_generation (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    generation INTEGER NOT NULL DEFAULT 0
);

-- The last network-side TLS verdict for every certificate/host pair.  This is
-- evidence only: renewal never consumes it, so losing a row must not change an
-- issuance decision. Keeping it lets the read-only inventory survive a daemon
-- restart without pretending the endpoint was never checked.
CREATE TABLE IF NOT EXISTS probe_samples (
    cert_name   TEXT NOT NULL,
    host        TEXT NOT NULL,
    match       INTEGER NOT NULL DEFAULT 0,
    trusted     INTEGER NOT NULL DEFAULT 0,
    not_after   INTEGER NOT NULL DEFAULT 0,
    problem_kind TEXT NOT NULL DEFAULT '',
    observed_at INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (cert_name, host)
);
`
